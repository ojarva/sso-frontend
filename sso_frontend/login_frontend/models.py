#pylint: disable-msg=C0301
from distutils.version import LooseVersion
from django.conf import settings
from django.contrib.auth import logout as django_logout
from django.db import models
from django.utils import timezone
from random import choice, randint
import datetime
import httpagentparser
import logging
import pyotp
import re
import subprocess
import sys
import os
import time
import uuid

log = logging.getLogger(__name__)

__all__ = ["create_browser_uuid", "EmergencyCodes", "EmergencyCode", "add_user_log", "Log", "Browser", "BrowserLogin", "BrowserUsers", "User", "AuthenticatorCode", "KeystrokeSequence", "BrowserDetails"]

def custom_log(request, message, **kwargs):
    """ Automatically logs username, remote IP and bid_public """
    custom_log_inner(request, message, **kwargs)

def custom_log_inner(request, message, **kwargs):
    """ Additional method call to get proper entry from call stack. """
    try:
        raise Exception
    except:
        stack = sys.exc_info()[2].tb_frame.f_back
    if stack is not None:
        stack = stack.f_back
    while hasattr(stack, "f_code"):
        co = stack.f_code
        filename = os.path.normcase(co.co_filename)
        filename = co.co_filename
        lineno = stack.f_lineno
        co_name = co.co_name
        break

    level = kwargs.get("level", "info")
    method = getattr(log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("[%s:%s:%s] %s - %s - %s - %s", filename, lineno, co_name,
                            remote_addr, username, bid_public, message)


def create_browser_uuid():
    """ Returns 37 characters unique ID as a string """
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


def add_user_log(request, message, status="question", **kwargs):
    if request.browser is None or request.browser.user is None:
        return
    bid_public = kwargs.get("bid_public")
    if not bid_public:
        bid_public = request.browser.bid_public
    obj = Log.objects.create(user=request.browser.user, bid_public=bid_public, message=message, remote_ip=request.META.get("REMOTE_ADDR"), status=status)
    obj.save()

class Log(models.Model):
    user = models.ForeignKey('User')
    timestamp = models.DateTimeField(auto_now_add=True)
    bid_public = models.CharField(max_length=37, null=True, blank=True)
    remote_ip = models.CharField(max_length=47, null=True, blank=True)
    message = models.TextField()
    status = models.CharField(max_length=30, default="question")

    class Meta:
        ordering = ["-timestamp"]

    def __unicode__(self):
        return u"%s %s@%s with %s: %s (%s)" % (self.timestamp, self.user, self.remote_ip, self.bid_public, self.message, self.status)

class Browser(models.Model):

    class Meta:
        ordering = ["-created"]

    def __unicode__(self):
        return u"%s: %s" % (self.bid_public, self.ua)

    L_UNAUTH = 0
    L_PUBLIC = 1
    L_BASIC = 2
    L_STRONG = 3
    L_STRONG_SKIPPED = 4
    A_AUTH_LEVEL = (
      (L_UNAUTH, 'Unauthenticated'),
      (L_PUBLIC, 'Access to public content'),
      (L_BASIC, 'Basic authentication'),
      (L_STRONG, 'Strong authentication'),
      (L_STRONG_SKIPPED, 'Authenticated with strong authentication, but with skipped auth')
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
    auth_level_valid_until = models.DateTimeField(null=True, blank=True)

    auth_state = models.DecimalField(max_digits=2, decimal_places=0, choices=A_AUTH_STATE, default=S_REQUEST_BASIC)
    auth_state_valid_until = models.DateTimeField(null=True, blank=True)
    
    sms_code = models.CharField(max_length=10, null=True, blank=True)
    sms_code_id = models.CharField(max_length=5, null=True, blank=True)
    sms_code_generated_at = models.DateTimeField(null=True, blank=True)

    authenticator_qr_nonce = models.CharField(max_length=37, null=True, blank=True)

    forced_sign_out = models.BooleanField(default=False)

    def has_any_activity(self):
        if self.user != None:
            return True
        if BrowserUsers.objects.filter(browser=self).count() > 0:
            return True
        if BrowserLogin.objects.filter(browser=self).count() > 0:
            return True
        if Log.objects.filter(bid_public=self.bid_public).count() > 0:
            return True


    def get_cookie(self):
        return [
           (Browser.C_BID, {"value": self.bid, "secure": settings.SECURE_COOKIES, "httponly": True, "max_age": time.time() + 86400 * 1000}),
           (Browser.C_BID_PUBLIC, {"value": self.bid_public, "secure": settings.SECURE_COOKIES, "httponly": True, "max_age": time.time() + 86400 * 1000}),
           (Browser.C_BID_SESSION, {"value": self.bid_session, "secure": settings.SECURE_COOKIES, "httponly": True})
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
            validity_time = datetime.timedelta(hours=10)
        else:
            if self.save_browser:
                validity_time = datetime.timedelta(days=14)
            else:
                validity_time = datetime.timedelta(days=1)
        self.auth_state_valid_until = timezone.now() + validity_time
        self.save()

    def set_auth_level(self, level):
        # TODO: logic for determining proper timeouts
        self.auth_level = level
        if self.user.emulate_legacy:
            validity_time = datetime.timedelta(hours=10)
        else:
            if self.save_browser:
                validity_time = datetime.timedelta(days=14)
            else:
                validity_time = datetime.timedelta(days=1)
        self.auth_level_valid_until = timezone.now() + validity_time
        self.save()

        if self.user:
            (browser_user, _) = BrowserUsers.objects.get_or_create(browser=self, user=self.user)
            if level >= browser_user.max_auth_level:
                browser_user.auth_timestamp = timezone.now()
            if level > browser_user.max_auth_level:
                browser_user.max_auth_level = level
            browser_user.save()

    def get_auth_state_level(self):
        # TODO: logic for determining proper authentication state
        if not self.user:
            return (Browser.S_REQUEST_BASIC, Browser.L_UNAUTH)

        # If valid_until has been expired for 60 days, require more authentication
        if self.auth_state_valid_until and self.auth_state_valid_until < timezone.now() - datetime.timedelta(days=60):
            return (Browser.S_REQUEST_BASIC, Browser.L_UNAUTH)

        # If valid_until has been expired for 60 days, require more authentication
        if self.auth_level_valid_until and self.auth_level_valid_until < timezone.now() - datetime.timedelta(days=60):
            return (Browser.S_REQUEST_BASIC, Browser.L_UNAUTH)

        if not self.auth_state_valid_until or self.auth_state_valid_until < timezone.now() or not self.auth_level_valid_until or self.auth_level_valid_until < timezone.now():
            if self.auth_level == Browser.L_STRONG_SKIPPED:
                # Authenticated to strong authentication, but with skipping. Request strong
                # authentication again, except for legacy mode.
                if self.user.emulate_legacy:
                    # Emulating legacy mode - ask for basic authentication.
                    return (Browser.S_REQUEST_BASIC, Browser.L_PUBLIC)
                else:
                    # User hit "skip". Ask for strong authentication again.
                    return (Browser.S_REQUEST_STRONG, Browser.L_BASIC)

            elif self.auth_level == Browser.L_STRONG:
                # Strong authentication - request basic authentication again
                return (Browser.S_REQUEST_BASIC_ONLY, Browser.L_PUBLIC)

            elif self.auth_level == Browser.L_BASIC:
                # Basic authentication - request both basic and strong authentication again.
                return (Browser.S_REQUEST_BASIC, Browser.L_UNAUTH)

            else:
                # Unauthenticated - request both basic and strong authentication.
                return (Browser.S_REQUEST_BASIC, Browser.L_UNAUTH)

        return (self.auth_state, self.auth_level)

    def get_auth_state(self):
        (auth_state, auth_level) = self.get_auth_state_level()
        return auth_state

    def get_auth_level(self):
        (auth_state, auth_level) = self.get_auth_state_level()
        return auth_level

    def is_authenticated(self):
        if self.get_auth_level() >= Browser.L_STRONG and self.get_auth_state() == Browser.S_AUTHENTICATED:
            return True
        return False

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
        # TODO: futurice
        return """Your one-time password #%s for Futurice SSO is below:



%s""" % (sms_code_id, sms_code)

    def generate_sms(self, length=5):
        """ Generates new SMS code, but does not send the message.
        Returns (code_id, sms_code) tuple. code_id is random
        id for code, to avoid confusion with duplicate/old messages. """
        code = ""
        for _ in range(length):
            code += str(randint(0, 9))
        self.sms_code = code
        self.sms_code_generated_at = timezone.now()
        self.sms_code_id = randint(0, 999)
        self.save()
        return (self.sms_code_id, self.sms_code)

    def logout(self, request = None):
        """ User requested logout.

        This cleans up browser-specific information, including
        - user object
        - SMS authentication codes
        - Authentication state
        - If request object was provided, Django user object.
        """
        if request:
            custom_log(request, "Logging out")
        else:
            log.info("Logging out: bid=%s" % self.bid)
        self.revoke_sms()
        self.user = None
        self.save_browser = False
        self.auth_level = Browser.L_UNAUTH
        self.auth_state = Browser.S_REQUEST_BASIC
        self.auth_level_valid_until = None
        self.auth_state_valid_until = None
        self.authenticator_qr_nonce = None
        if request is not None:
            django_logout(request)
        self.save()

    def get_readable_ua(self):
        """ Returns user-agent in readable format """
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

    UA_DETECT = {
        ".*Maemo": ["linux", "mobile"],
        ".*Opera.*S60": ["mobile"],
        ".*Opera.*Android": ["android", "mobile"],
        ".*Opera.*Windows.*Mini": ["windows", "mobile"],
        ".*Opera.*iPhone": ["apple", "mobile"],
        ".*Opera.*iPad": ["apple", "tablet"],
        ".*Android.*Mobile": ["android", "mobile"],
        "^.*Android((?!Mobile).)*$": ["android", "tablet"],
        ".*\(iPad": ["apple", "tablet"],
        ".*\(iPhone": ["apple", "mobile"],
        ".*Macintosh": ["apple", "laptop"],
        ".*BlackBerry": ["mobile"],
        ".*Bolt": ["mobile"],
        ".*Symbian": ["mobile"],
        ".*Fennec": ["mobile"],
        ".*IEMobile": ["mobile"],
        ".*Mobile": ["mobile"],
        ".*[Aa]ndroid": ["android", "mobile"],
        ".*Windows Phone": ["windows", "mobile"],
        ".*Windows.*Mobile": ["windows", "mobile"],
        ".*Windows": ["windows"],
        ".*Linux": ["linux"],
    }

    def get_ua_icons(self):
        """ Returns Font Awesome icons for platform and OS """
        icon = ["question"] # By default, show unknown icon
        for (regex, icons) in self.UA_DETECT.iteritems():
            if re.match(regex, self.ua):
                return icons
        return icon

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

    class Meta:
        ordering = ["-auth_timestamp", "sso_provider", "remote_service"]

    def __unicode__(self):
        return u"%s with %s: %s to %s at %s" % (self.user.username, self.browser.get_readable_ua(), self.sso_provider, self.remote_service, self.auth_timestamp)

    browser = models.ForeignKey("Browser")
    user = models.ForeignKey("User")

    sso_provider = models.CharField(max_length=30, help_text="(Internal) name of SSO provider")
    remote_service = models.CharField(max_length=1000, null=True, blank=True, help_text="URL to remote service, if available")
    message = models.CharField(max_length=1000, null=True, blank=True, help_text="Optional user-readable information")
    auth_timestamp = models.DateTimeField(help_text="Timestamp of authentication")

    can_logout = models.BooleanField(default=False, help_text="True if session can be closed remotely")
    expires_at = models.DateTimeField(null=True, help_text="Ticket expiration time, if available")
    expires_session = models.BooleanField(default=True, help_text="True if ticket/cookie expires when browser is closed")

    signed_out = models.BooleanField(default=False, help_text="Session has been closed")

class BrowserUsers(models.Model):

    class Meta:
        ordering = ["-auth_timestamp"]

    def __unicode__(self):
        return u"%s with %s at %s (%s)" % (self.user.username, self.browser.get_readable_ua(), self.auth_timestamp, self.max_auth_level)

    user = models.ForeignKey('User')
    browser = models.ForeignKey('Browser')
    auth_timestamp = models.DateTimeField(null=True, help_text="Timestamp of the latest authentication")
    max_auth_level = models.CharField(max_length=1, choices=Browser.A_AUTH_LEVEL, default=Browser.L_UNAUTH, help_text="Highest authentication level for this User/Browser combination")

    remote_ip = models.GenericIPAddressField(null=True, blank=True, help_text="Last remote IP address (active)")
    last_seen = models.DateTimeField(null=True)

    remote_ip_passive = models.GenericIPAddressField(null=True, blank=True, help_text="Last remote IP address")
    last_seen_passive = models.DateTimeField(null=True)

class BrowserDetails(models.Model):
    """ Holds additional information for Browser """
    browser = models.ForeignKey("Browser")
    timestamp = models.DateTimeField()

    remote_clock_offset = models.IntegerField(null=True, blank=True)
    remote_clock_time = models.CharField(max_length=28, null=True, blank=True)

    performance_performance = models.TextField(null=True, blank=True)
    performance_memory = models.TextField(null=True, blank=True)
    performance_timing = models.TextField(null=True, blank=True)
    performance_navigation = models.TextField(null=True, blank=True)

    resolution = models.TextField(null=True, blank=True)
    plugins = models.TextField(null=True, blank=True)

class KeystrokeSequence(models.Model):
    OTP_AUTHENTICATOR = 0
    OTP_SMS = 1
    USERNAME = 2
    PASSWORD = 3
    KEYSTROKE_FIELD = (
      (OTP_AUTHENTICATOR, "OTP to Authenticator field"),
      (OTP_SMS, "OTP to SMS field"),
      (USERNAME, "Username field"),
      (PASSWORD, "Password field"),
    )

    browser = models.ForeignKey("Browser", null=True)
    user = models.ForeignKey("User")    

    resolution = models.CharField(max_length=30) # Screen resolution, used to determine whether external display was used.
    fieldname = models.CharField(max_length=1, choices=KEYSTROKE_FIELD)
    was_correct = models.BooleanField()
    timestamp = models.DateTimeField()
    timing = models.TextField()


class UsedOTP(models.Model):
    """ Stores list of used OTPs."""

    def __unicode__(self):
        return u"%s: %s at %s from %s" % (self.user, self.code, self.used_at, self.used_from)

    user = models.ForeignKey('User')
    code = models.CharField(max_length=15)
    used_at = models.DateTimeField(auto_now_add=True)
    used_from = models.GenericIPAddressField(null=True, blank=True)

class User(models.Model):

    class Meta:
        ordering = ["username"]

    def __unicode__(self):
        return u"%s" % self.username

    username = models.CharField(max_length=50, primary_key=True)
    is_admin = models.BooleanField(default=False)

    strong_configured = models.BooleanField(default=False, help_text="True if user has saved strong authentication preferences")
    strong_authenticator_secret = models.CharField(max_length=30, null=True, blank=True, help_text="Secret for TOTP generation")
    strong_authenticator_generated_at = models.DateTimeField(null=True, help_text="Timestamp of generating authenticator secret")
    strong_authenticator_used = models.BooleanField(default=False, help_text="True if user has used authenticator")

    strong_sms_always = models.BooleanField(default=False, help_text="True if user wants to always use SMS")

    strong_skips_available = models.IntegerField(default=0)

    # If this is True, no strong authentication is required, and login is valid only for 12 hours
    emulate_legacy = models.BooleanField(default=False)

    primary_phone_changed = models.BooleanField(default=False, help_text="True if users strong authentication preferences were revoked because primary phone number was changed")

    email = models.EmailField(null=True, blank=True)
    primary_phone = models.CharField(max_length=30, null=True, blank=True)
    secondary_phone = models.CharField(max_length=30, null=True, blank=True)
    primary_phone_refresh = models.DateTimeField(null=True)
    secondary_phone_refresh = models.DateTimeField(null=True)

    user_tokens = models.CharField(max_length=255, null=True, blank=True, help_text="List of pubtkt tokens")


    def sign_out_all(self, **kwargs):
        browsers = Browser.objects.filter(user=self)
        request = kwargs.get("request")

        for browser in browsers:
            browser.logout(request)

            bid_public = browser.bid_public
            if request:
                remote_ip = request.META.get("REMOTE_ADDR")
            else:
                remote_ip = None

            status = "sign-out"
            message = "Signed out"
            if kwargs.get("admin_logout"):
                status = "exclamation-circle"
                message = "%s remotely terminated this session" % kwargs.get("admin_logout")
                browser.forced_sign_out = True
                browser.save()
            elif kwargs.get("remote_logout"):
                message = "You remotely signed out this browser"
            Log.objects.create(user=self, bid_public=bid_public, status=status, message=message, remote_ip=remote_ip)

    def reset(self):
        self.strong_configured = False
        self.strong_authenticator_secret = None
        self.strong_authenticator_generated_at = None
        self.strong_authenticator_used = False
        self.save()

    def gen_authenticator(self):
        """ Generates and stores new secret for authenticator. """
        timestamp = timezone.now()
        self.strong_authenticator_secret = pyotp.random_base32()
        self.strong_authenticator_generated_at = timestamp
        self.save()
        AuthenticatorCode.objects.create(user=self, generated_at=timestamp, authenticator_secret=self.strong_authenticator_secret)
        return self.strong_authenticator_secret

    def validate_authenticator_code(self, code, request):
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
            totp_code = ("000000"+str(totp.at(timestamp)))[-6:]
            custom_log(request, "Comparing '%s' and '%s'" % (totp_code, code), level="debug")
            if str(code) == totp_code:
                (obj, created) = UsedOTP.objects.get_or_create(user=self, code=code)
                if created:
                    if request:
                        obj.used_from = request.META.get("REMOTE_ADDR")
                        obj.save()
                else:
                    return (False, "OTP was already used. Please wait for 30 seconds and try again.")
                return (True, None)

        # Either timestamp is way off or user entered incorrect OTP.
        custom_log(request, "Invalid OTP - does not match to current Authenticator code", level="info")

        for time_diff in range(-900, 900, 30):
            timestamp = time.time() + time_diff
            totp_code = ("000000"+str(totp.at(timestamp)))[-6:]
            if str(code) == totp_code:
                custom_log(request, "User clock is off by %s seconds" % time_diff, level="warn")
                add_user_log(request, "Clock of your mobile phone is off by %s seconds" % time_diff, status="clock-o")
                message = "Incorrect code. It seems your clock is off by about %s seconds" % time_diff
                if time_diff < 0:
                    message += ", or you waited too long before entering the code"
                message += "."
                return (False, message)

        # No match from current authentication even with time offset. Try old codes.
        old_authenticators = AuthenticatorCode.objects.filter(user=self)
        for authenticator in old_authenticators:
            totp = pyotp.TOTP(authenticator.authenticator_secret)
            for time_diff in range(-900, 900, 30):
                timestamp = time.time() + time_diff
                totp_code = ("000000"+str(totp.at(timestamp)))[-6:]
                if str(code) == totp_code:
                    custom_log(request, "User tried to use authenticator configured at %s" % authenticator.generated_at, level="info")
                    if abs(time_diff) < 35:
                        message = "You tried to use old Authenticator configuration, generated at %s. If you don't have newer configuration, please sign in with SMS and reconfigure Authenticator." % authenticator.generated_at
                    else:
                        message = "You tried to use old Authenticator configuration, generated at %s. If you don't have newer configuration, please sign in with SMS and reconfigure Authenticator. Also, your clock seems to be off by about %s seconds" % (authenticator.generated_at, time_diff)
                        custom_log(request, "User clock is off by %s seconds" % time_diff, level="warn")
                    return (False, message)

        return (False, "Incorrect OTP code.")


    def refresh_strong(self, email, phone1, phone2, **kwargs):
        """ Refreshes strong authentication details,
        and revokes configuration when needed. """
        changed = False
        created = kwargs.get("created", False)

        if phone2 != self.secondary_phone:
            self.secondary_phone = phone2
            self.secondary_phone_refresh = timezone.now()

        if email != self.email:
            self.email = email

        if phone1 == None and phone2 == None:
            if not self.emulate_legacy:
                self.emulate_legacy = True
                changed = True

        if phone1 == self.primary_phone:
            # All is fine. Carry on.
            self.save()
            return changed

        if phone1 != self.primary_phone:
            # Strong auth is configured but primary phone changed.
            changed = True
            self.primary_phone = phone1
            self.primary_phone_refresh = timezone.now()
            self.strong_configured = False
            if created:
                self.primary_phone_changed = False
            else:
                self.primary_phone_changed = True
            self.strong_authenticator_secret = None
            self.strong_authenticator_used = False
        self.save()
        return changed

class AuthenticatorCode(models.Model):
    user = models.ForeignKey("User")
    generated_at = models.DateTimeField()
    authenticator_secret = models.CharField(max_length=30, help_text="Secret for TOTP generation")
