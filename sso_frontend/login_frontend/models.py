from distutils.version import LooseVersion
from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.timesince import timeuntil
from random import choice, randint
from django.contrib.auth import logout as django_logout
import datetime
import httpagentparser
import phonenumbers
import pyotp
import subprocess
import time
import uuid
import logging

log = logging.getLogger(__name__)


def create_browser_uuid():
    return str(uuid.uuid4())


class EmergencyCodes(models.Model):
    user = models.ForeignKey("User", primary_key=True)
    generated_at = models.DateTimeField(null=True)
    current_code = models.ForeignKey("EmergencyCode", null=True)

    def use_code(self, code):
        if self.current_code is None:
            return False
        if self.current_code.code_val == code:
            self.current_code.delete()
            if self.codes_left() > 0:
                self.current_code = choice(EmergencyCode.objects.filter(codegroup=self))
            else:
                self.current_code = None
            self.save()
            return True
        return False

    def valid(self):
        return self.codes_left() > 0

    def codes_left(self):
        return EmergencyCode.objects.filter(codegroup=self).count()

    def revoke_codes(self):
        self.current_code = None
        self.generated_at = None
        self.save()
        EmergencyCode.objects.filter(codegroup=self).delete()

    def generate_code(self):
        p = subprocess.Popen(["pwgen", "15", "1"], stdout=subprocess.PIPE)
        (code, _) = p.communicate()
        return code.strip()

    def generate_codes(self, num):
        """ Revokes old codes and generates new ones """
        self.revoke_codes()
        for code_id in range(num):
            code_val = self.generate_code()
            code = EmergencyCode(codegroup=self, code_id=code_id, code_val=code_val)
            code.save()
        if self.codes_left() > 0:
            self.current_code = choice(EmergencyCode.objects.filter(codegroup=self))
        

class EmergencyCode(models.Model):
    codegroup = models.ForeignKey("EmergencyCodes")
    code_id = models.IntegerField()
    code_val = models.CharField(max_length=20)

    class Meta:
        unique_together = (("codegroup", "code_id"), ("codegroup", "code_val"))


def add_log_entry(request, message):
    if request.browser is None or request.browser.user is None:
        return
    obj = Log.objects.create(user=request.browser.user, bid_public=request.browser.bid_public, message=message, remote_ip=request.META.get("REMOTE_ADDR"))
    obj.save()

class Log(models.Model):
    user = models.ForeignKey('User')
    timestamp = models.DateTimeField(auto_now_add=True)
    bid_public = models.CharField(max_length=37)
    remote_ip = models.CharField(max_length=47, null=True, blank=True)
    message = models.TextField()

class Browser(models.Model):
    L_UNAUTH = 0
    L_PUBLIC = 1
    L_BASIC = 2
    L_STRONG = 3
    A_AUTH_LEVEL = (
      (L_UNAUTH, 'Unauthenticated'),
      (L_PUBLIC, 'Access to public content'),
      (L_BASIC, 'Basic authentication'),
      (L_STRONG, 'Strong authentication')
    )


    S_REQUEST_BASIC = 0
    S_REQUEST_STRONG = 1
    S_REQUEST_BASIC_ONLY = 2
    S_AUTHENTICATED = 3
    A_AUTH_STATE = (
      (S_REQUEST_BASIC, 'Request basic authentication'),
      (S_REQUEST_BASIC_ONLY, 'Request only basic authentication'),
      (S_REQUEST_STRONG, 'Request strong authentication'),
      (S_AUTHENTICATED, 'Authenticated'),
    )

    C_BID = "v2browserid"
    C_BID_PUBLIC = "v2public-browserid"
    C_BID_SESSION = "v2sessionbid"

    bid = models.CharField(max_length=37, primary_key=True) # UUID
    bid_session = models.CharField(max_length=37) # UUID
    bid_public = models.CharField(max_length=37) # UUID

    user = models.ForeignKey('User', null=True)
    ua = models.CharField(max_length=250) # browser user agent

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    save_browser = models.BooleanField(default=False)

    auth_level = models.DecimalField(max_digits=2, decimal_places=0, choices=A_AUTH_LEVEL, default=L_UNAUTH)
    auth_level_valid_until = models.DateTimeField(null=True,blank=True)

    auth_state = models.DecimalField(max_digits=2, decimal_places=0, choices=A_AUTH_STATE, default=S_REQUEST_BASIC)
    auth_state_valid_until = models.DateTimeField(null=True, blank=True)
    
    sms_code = models.CharField(max_length=10, null=True, blank=True)
    sms_code_id = models.CharField(max_length=5, null=True, blank=True)
    sms_code_generated_at = models.DateTimeField(null=True, blank=True)

    authenticator_qr_nonce = models.CharField(max_length=37, null=True, blank=True)

    def get_cookie(self):
        return [
           (Browser.C_BID, {"value": self.bid, "secure": True, "httponly": True, "domain": "login.futurice.com", "max_age": time.time() + 86400 * 1000}),
           (Browser.C_BID_PUBLIC, {"value": self.bid_public, "secure": True, "httponly": True, "domain": "login.futurice.com", "max_age": time.time() + 86400 * 1000}),
           (Browser.C_BID_SESSION, {"value": self.bid_session, "secure": True, "httponly": True, "domain": "login.futurice.com"})
        ]

    def revoke_sms(self):
        self.sms_code = None
        self.sms_code_id = None
        self.sms_code_generated_at = None
        self.save()

    def set_auth_state(self, state):
        # TODO: logic for determining proper timeouts
        self.auth_state = state
        if self.user.emulate_legacy:
            validity_time = datetime.timedelta(hours=12)
        else:
            validity_time = datetime.timedelta(days=1)
        self.auth_state_valid_until = timezone.now() + validity_time
        self.save()

    def set_auth_level(self, level):
        # TODO: logic for determining proper timeouts
        self.auth_level = level
        if self.user.emulate_legacy:
            validity_time = datetime.timedelta(hours=12)
        else:
            validity_time = datetime.timedelta(days=1)
        self.auth_level_valid_until = timezone.now() + validity_time
        self.save()

    def get_auth_state(self):
        # TODO: logic for determining proper authentication state
        return self.auth_state

    def get_auth_level(self):
        # TODO: logic for determining proper authentication level
        return self.auth_level

    def valid_sms_exists(self):
        if not self.sms_code or not self.sms_code_generated_at:
            return False
        otp_age = timezone.now() - self.sms_code_generated_at
        otp_age_s = otp_age.days * 86400 + otp_age.seconds
        if otp_age_s > 900:
            return False
        return True

    def validate_sms(self, otp):
        if self.sms_code is None:
            return (False, "No OTP code exists for this browser.")
        if otp != self.sms_code:
            return (False, None)
        if not self.valid_sms_exists():
            self.revoke_sms()
            return (False, "OTP was valid, but expired (15 minutes). Please request a new code.")
        self.revoke_sms()
        return (True, None)        

    def generate_sms_text(self, length=5):
        """ Generates new SMS code and returns contents of SMS.

        Formatting of the message, including line breaks, is important to
        prevent exposure to lock screen.
        """
        (sms_code_id, sms_code) = self.generate_sms(length)
        return """Your one-time password #%s for Futurice SSO is below:



%s""" % (sms_code_id, sms_code)

    def generate_sms(self, length=5):
        """ Generates new SMS code, but does not send the message.
        Returns (code_id, sms_code) tuple. code_id is random
        id for code, to avoid confusion with duplicate/old messages. """
        code = ""
        for _ in range(length):
            code += str(randint(0,9))
        self.sms_code = code
        self.sms_code_generated_at = timezone.now()
        self.sms_code_id = randint(0, 999)
        self.save()
        return (self.sms_code_id, self.sms_code)

    def logout(self, request = None):
        """ User requested logout. In practice, cleanup all associations between user and browser. """
        log.info("Logging out: %s" % self.bid)
        self.revoke_sms()
        self.user = None
        self.save_browser = False
        self.auth_level = Browser.L_UNAUTH
        self.auth_state = Browser.S_REQUEST_BASIC
        self.auth_level_valid_until = None
        self.auth_state_valid_until = None
        if request is not None:
            django_logout(request)
        self.save()


    def get_readable_ua(self):
        data = httpagentparser.detect(self.ua)
        browser = None
        os = None
        if "browser" in data and "name" in data["browser"]:
                browser = data["browser"]["name"]
        if "dist" in data and "name" in data["dist"]:
            if "version" in data["dist"]:
                os = "%s (%s)" % (data["dist"]["name"], data["dist"]["version"])
            else:
                os = data["dist"]["name"]

        elif "platform" in data and "name" in data["platform"]:
            if "version" in data["platform"]:
                os = "%s (%s)" % (data["platform"]["name"], data["platform"]["version"])
            else:
                os = data["platform"]["name"]
        elif "os" in data and "name" in data["os"]:
            os = data["os"]["name"]
        if browser:
            if os:
                return "%s on %s" % (browser, os)
            else:
                return "%s on unknown platform" % (browser)
        return self.ua

    def compare_ua(self, ua):
        # TODO: Validate this code.
        if ua == self.ua:
            return True
        old_ua = httpagentparser.detect(self.ua)
        new_ua = httpagentparser.detect(ua)
        keys = {"os": ["version", "name"], "browser": ["version", "name"]}
        if "os" in old_ua and "os" in new_ua:
            if old_ua["os"] != new_ua["os"]:
                return False
        if "browser" in old_ua and "browser" in new_ua:
            ou = old_ua["browser"]
            nu = new_ua["browser"]
            if ou.get("name") != nu.get("name"):
                return False
            if ou.get("version") == nu.get("version"):
                return True
            try:
                ou_v = LooseVersion(ou.get("version"))
                nu_v = LooseVersion(nu.get("version"))
            except AttributeError:
                return False # Something fishy with version strings
            if nu_v < ou_v:
                return False # downgraded browser version
        return True

class BrowserLogin(models.Model):
    browser = models.ForeignKey("Browser")
    user = models.ForeignKey("User")

    sso_provider = models.CharField(max_length=30)
    remote_service = models.CharField(max_length=1000, null=True, blank=True)
    message = models.CharField(max_length=1000, null=True, blank=True)
    auth_timestamp = models.DateTimeField()

    can_logout = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True)
    expires_session = models.BooleanField(default=True)

    signed_out = models.BooleanField(default=False)

class BrowserUsers(models.Model):
    user = models.ForeignKey('User')
    browser = models.ForeignKey('Browser')
    auth_timestamp = models.DateTimeField(null=True)
    max_auth_level = models.CharField(max_length=1, choices=Browser.A_AUTH_LEVEL, default=Browser.L_UNAUTH)

    remote_ip = models.GenericIPAddressField(null=True,blank=True)
    last_seen = models.DateTimeField(null=True)

class UsedOTP(models.Model):
    """ Stores list of used OTPs."""

    user = models.ForeignKey('User')
    code = models.CharField(max_length=15)
    used_at = models.DateTimeField(auto_now_add=True)
    used_from = models.CharField(max_length=46, null=True, blank=True) # TODO

class User(models.Model):
    username = models.CharField(max_length=50, primary_key=True)

    strong_configured = models.BooleanField(default=False)
    strong_authenticator_secret = models.CharField(max_length=30, null=True, blank=True)
    strong_authenticator_generated_at = models.DateTimeField(null=True)
    strong_authenticator_used = models.BooleanField(default=False)

    strong_sms_always = models.BooleanField(default=False)

    # If this is True, no strong authentication is required, and login is valid only for 12 hours
    emulate_legacy = models.BooleanField(default=False)

    primary_phone_changed = models.BooleanField(default=False)

    email = models.EmailField(null=True, blank=True)
    primary_phone = models.CharField(max_length=30, null=True, blank=True)
    secondary_phone = models.CharField(max_length=30, null=True, blank=True)
    primary_phone_refresh = models.DateTimeField(null=True)
    secondary_phone_refresh = models.DateTimeField(null=True)

    user_tokens = models.CharField(max_length=255, null=True, blank=True)

    def gen_authenticator(self):
        """ Generates and stores new secret for authenticator. """
        self.strong_authenticator_secret = pyotp.random_base32()
        self.strong_authenticator_generated_at = timezone.now()
        self.save()
        return self.strong_authenticator_secret

    def validate_authenticator_code(self, code):
        """ Validates authenticator OTP. 

        Returns (status, message) tuple.
        - status is True if succeeded, False if failed.
        - message is either None or user-readable string
          describing the problem.
        """
 
        if not self.strong_authenticator_secret:
            return (False, "Authenticator is not configured")

        totp = pyotp.TOTP(self.strong_authenticator_secret)
        for timestamp in [time.time() - 30, time.time(), time.time() + 30]:
            totp_code = totp.at(timestamp)
            log.info("Comparing '%s' and '%s'" % (totp_code, code))
            if str(code) == str(totp.at(timestamp)):
                (obj, created) = UsedOTP.objects.get_or_create(user=self, code=code)
                if created:
                    obj.save()
                else:
                    return (False, "OTP was already used. Please wait for 30 seconds and try again.")
                return (True, None)
        return (False, "Incorrect OTP code.")


    def refresh_strong(self, email, phone1, phone2):
        """ Refreshes strong authentication details,
        and revokes configuration when needed. """
        if phone2 != self.secondary_phone:
            self.secondary_phone = phone2
            self.secondary_phone_refresh = timezone.now()

        if email != self.email:
            self.email = email

        if phone1 == self.primary_phone:
            # All is fine. Carry on.
            self.save()
            return

        if phone1 != self.primary_phone:
            # Strong auth is configured but primary phone changed.
            self.primary_phone = phone1
            self.primary_phone_refresh = timezone.now()
            self.strong_configured = False
            self.primary_phone_changed = True
            self.strong_authenticator_secret = None
            self.strong_authenticator_used = False
        self.save()
