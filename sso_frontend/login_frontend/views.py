from StringIO import StringIO
from django.contrib import auth as django_auth
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.timesince import timeuntil
from django.views.decorators.http import require_http_methods
from helpers import *
from ldap_auth import LdapLogin
from login_frontend.forms import *
from models import *
from ratelimit.decorators import ratelimit
from ratelimit.helpers import is_ratelimited
from send_sms import send_sms
from utils import *
import Cookie
import auth_pubtkt
import datetime
import dateutil.parser
import json
import pyotp
import qrcode
import redis
import time
import urllib
import logging


log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger("users.%s" % __name__)

def custom_log(request, message, **kwargs):
    level = kwargs.get("level", "info")
    method = getattr(user_log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    if request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("%s - %s - %s - %s", remote_addr, username, bid_public, message)


def protect_view(current_step, **main_kwargs):
    """ After this is executed, kwargs["required_level"] is satisfied.
        If not given, Browser.L_STRONG is required.
        Otherwise, user is redirected to appropriate login step.
        This never redirects user to the originating service.
    """

    def redir_view(next_view, resp):
        if current_step == next_view:
            return None
        return resp

    def wrap(f):
        def inner(request, *args, **kwargs):
            required_level = main_kwargs.get("required_level", Browser.L_STRONG)
            get_params = request.GET
            browser = request.browser
            if browser is None:
                current_level = Browser.L_UNAUTH
            else:
                current_level = int(browser.auth_level)


            if current_level >= required_level:
                # Authentication level is already satisfied
                # Execute requested method.
                return f(request, *args, **kwargs)

            # Authentication level is not satisfied. Determine correct step for next page.
            if browser is None:
                # User is not authenticated. Go to first step.
                return redir_view("firststepauth", custom_redirect('login_frontend.views.firststepauth', get_params))

            if browser.auth_state == Browser.S_REQUEST_STRONG:
                # The next step is strong authentication. Check state validity.
                if browser.auth_state_valid_until < timezone.now():
                    # Authentication timed out. Go back to first step.
                    return redir_view("firststepauth", custom_redirect('login_frontend.view.firststepauth', get_params))
                # Login is still valid. Go to second step authentication
                return redir_view("secondstepauth", custom_redirect("login_frontend.views.secondstepauth", get_params))

            # Requested authentication level is not satisfied, and user is not proceeding to the second step.
            # Start from the beginning.
            return redir_view("firststepauth", custom_redirect("login_frontend.views.firststepauth", get_params))

        return inner
    return wrap

def main_redir(request):
    """ Hack to enable backward compatibility with pubtkt.
    If "back" parameter is specified, forward to pubtkt provider. Otherwise,
    go to index page
    """
    if request.GET.get("back") != None:
        return custom_redirect("login_frontend.providers.pubtkt", request.GET)
    return custom_redirect("login_frontend.views.indexview", request.GET)

@require_http_methods(["GET", "POST"])
@ratelimit(rate='30/15s', ratekey="15s", block=True, method=["POST", "GET"])
@ratelimit(rate='500/10m', ratekey="10m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("indexview", required_level=Browser.L_BASIC)
def indexview(request):
    """ Index page: user is redirected
    here if no real destination is available. """

    # TODO: "valid until"
    ret = {}
    ret["username"] = request.browser.user.username
    ret["user"] = request.browser.user
    ret["get_params"] = urllib.urlencode(request.GET)
    auth_level = request.browser.get_auth_level()
    if auth_level == Browser.L_STRONG:
        ret["auth_level"] = "strong"
    elif auth_level == Browser.L_BASIC:
        ret["auth_level"] = "basic"


    response = render_to_response("indexview.html", ret, context_instance=RequestContext(request))
    return response

@protect_view("firststepauth", required_level=Browser.L_UNAUTH)
def firststepauth(request):
    """ Redirects user to appropriate first factor authentication.
    Currently only username/password query """
    return custom_redirect("login_frontend.views.authenticate_with_password", request.GET)

@protect_view("authenticate_with_password", required_level=Browser.L_UNAUTH)
def authenticate_with_password(request):
    """ Authenticate with username and password """

    ret = {}
    cookies = []
    if request.browser is not None:
        auth_state = request.browser.get_auth_state()
        if request.browser.get_auth_state() in (Browser.S_REQUEST_STRONG, ):
            # User is already in strong authentication. Redirect them there.
            return custom_redirect("login_frontend.views.secondstepauth", request.GET)
        if request.browser.get_auth_state() in (Browser.S_AUTHENTICATED, ):
            # User is already authenticated. Redirect back to SSO service.
            return redir_to_sso(request)
    else:
        # No Browser object is initialized. Create one.
        browser = Browser(bid=create_browser_uuid(), bid_public=create_browser_uuid(), ua=request.META.get("HTTP_USER_AGENT"))
        browser.save()
        cookies.extend(browser.get_cookie())
    if request.method == 'POST':
        form = AuthWithPasswordForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            auth = LdapLogin(username, password, r)
            auth_status = auth.login()
            if auth_status == True:
                # User authenticated successfully. Update AUTH_STATE and AUTH_LEVEL
                if request.browser.user is None:
                    (user, created) = User.objects.get_or_create(username=auth.username)
                    user.user_tokens = json.dumps(auth.get_auth_tokens())
                    user.save()
                    request.browser.user = user
                # TODO: no further authentication is necessarily needed. Determine these automatically.
                request.browser.set_auth_level(Browser.L_BASIC)
                request.browser.set_auth_state(Browser.S_REQUEST_STRONG)
                request.browser.save()

                add_log_entry(request, "Successfully logged in using username and password")
                custom_log(request, "Successfully logged in using username and password")
                return custom_redirect("login_frontend.views.secondstepauth", request.GET)
            else:
                if auth_status == "invalid_credentials":
                    ret["authentication_failed"] = True
                    custom_log(request, "Authentication failed. Invalid credentials", level="warn")
                    add_log_entry(request, "Authentication failed. Invalid credentials")
                else:
                    ret["message"] = auth_status 
                    custom_log(request, "Authentication failed: %s" % auth_status, level="warn")
                    add_log_entry(request, "Authentication failed: %s" % auth_status)
    else:
        form = AuthWithPasswordForm(request.POST)
    ret["form"] = form


    # Keep GET query parameters in form posts.
    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("authenticate_with_password.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        response.set_cookie(cookie_name, **cookie)
    return response


@protect_view("secondstepauth", required_level=Browser.L_BASIC)
def secondstepauth(request):
    """ Determines proper second step authentication method """
    assert request.browser is not None, "Second step authentication requested, but browser is None."
    assert request.browser.user is not None, "Second step authentication requested, but user is not specified."

    get_params = request.GET
    user = request.browser.user

    # If already authenticated with L_STRONG, redirect back to destination
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        return redir_to_sso(request)

    if not user.strong_configured:
        # User has not configured any authentication. Go to that pipe.
        return custom_redirect("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_sms_always:
        # Strong authentication has been configured, and user has requested to get SMS message.
        return custom_redirect("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_authenticator_secret:
        return custom_redirect("login_frontend.views.authenticate_with_authenticator", get_params)

    return HttpResponse("Second step auth: no proper redirect configured.")

@protect_view("authenticate_with_authenticator", required_level=Browser.L_BASIC)
def authenticate_with_authenticator(request):
    """ Authenticates user with Google Authenticator """


    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        return redir_to_sso(request)

    ret = {}
    user = request.browser.user
    assert user != None, "Browser is authenticated but no User object exists."

    if not user.strong_authenticator_secret:
        # Authenticator is not configured. Redirect back to secondstep main screen
        return custom_redirect("login_frontend.views.secondstepauth", request.GET)

    if request.method == "POST":
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data["otp"]
            (status, message) = user.validate_authenticator_code(form.cleaned_data["otp"])
            if not status:
                # If authenticator code did not match, also try latest SMS (if available).
                status, _ = request.browser.validate_sms(otp)
            if status:
                custom_log(request, "Second-factor authentication with Authenticator succeeded")
                add_log_entry(request, "Second-factor authentication with Authenticator succeeded")
                # Mark authenticator configuration as valid. User might have configured
                # authenticator but aborted without entering validation code.
                user.strong_authenticator_used = True
                user.save()
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                return redir_to_sso(request)
            else:
                custom_log(request, "Incorrect OTP provided: %s" % message, level="warn")
                add_log_entry(request, "Incorrect OTP provided: %s" % message)
                ret["invalid_otp"] = message
    else:
        form = OTPForm()


    ret["form"] = form
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)

    response = render_to_response("authenticate_with_authenticator.html", ret, context_instance=RequestContext(request))
    return response
       


@protect_view("authenticate_with_sms", required_level=Browser.L_BASIC)
def authenticate_with_sms(request):
    """ Authenticate user with SMS. 
    Accepts Authenticator codes too.
    """
    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        return redir_to_sso(request)

    user = request.browser.user
    cookies = []
    ret = {}
    if not (user.primary_phone or user.secondary_phone):
        # Phone numbers are not available.
        return HttpResponse("No phone number available")

    if not user.strong_configured:
        # No strong authentication is configured.
        ret["strong_not_configured"] = True
    if user.primary_phone_changed:
        # Phone number changed. For security reasons...
        ret["primary_phone_changed"] = True

    if request.method == "POST":
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data["otp"]
            status, message = request.browser.validate_sms(otp)
            if not status:
                # If OTP from SMS did not match, also test for Authenticator OTP.
                (status, _) = request.browser.user.validate_authenticator_code(otp)

            if status:
                # Authentication succeeded.
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                user.primary_phone_changed = False
                user.save()
                custom_log(request, "Second-factor authentication succeeded")
                add_log_entry(request, "Second-factor authentication succeeded")
                if not user.strong_configured:
                    # Strong authentication is not configured. Go to configuration view.
                    return custom_redirect("login_frontend.views.configure_strong", request.GET)
                # Redirect back to SSO service
                return redir_to_sso(request)
            else:
                if message:
                    ret["message"] = message
                    custom_log(request, "OTP login failed: %s" % message, level="warn")
                    add_log_entry(request, "OTP login failed: %s" % message)
                else:
                    custom_log(request, "Incorrect OTP", level="warn")
                    add_log_entry(request, "Incorrect OTP")
                    ret["authentication_failed"] = True
    else:
        form = OTPForm()

    if request.method == "GET" or request.GET.get("regen_sms") or not request.browser.valid_sms_exists():
        sms_text = request.browser.generate_sms_text()
        for phone in (user.primary_phone, user.secondary_phone):
            if phone:
                status = send_sms(phone, sms_text)
                custom_log(request, "Sent OTP to %s" % phone)
                add_log_entry(request, "Sent OTP code to %s" % phone)
                if not status:
                    ret["message"] = "Sending SMS to %s failed." % phone
                    custom_log(request, "Sending SMS to %s failed" % phone, level="warn")
                    add_log_entry(request, "Sending SMS to %s failed" % phone)

    ret["expected_sms_id"] = request.browser.sms_code_id
    ret["form"] = form
    ret["get_params"] = urllib.urlencode(request.GET)

    response = render_to_response("authenticate_with_sms.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        response.set_cookie(cookie_name, **cookie)
    return response

@protect_view("configure_strong", required_level=Browser.L_STRONG)
def configure_strong(request):
    """ Configuration view for general options. """
    user = request.browser.user
    browsers = Browser.objects.filter(user=user)
    ret = {}
    ret["browsers"] = browsers

    if request.method == "POST":
        if request.POST.get("always_sms") == "on":
            user.strong_configured = True
            user.strong_sms_always = True
            user.save()
        # TODO: disabling always_sms

    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    back_url = redir_to_sso(request, no_default=True)
    if back_url:
        ret["back_url"] = back_url.url
    response = render_to_response("configure_strong.html", ret, context_instance=RequestContext(request))
    return response


@protect_view("get_authenticator_qr", required_level=Browser.L_STRONG)
def get_authenticator_qr(request, **kwargs):
    """ Outputs QR code for Authenticator. Uses single_use_code to prevent
    reloading / linking. """
    if not request.browser.authenticator_qr_nonce == kwargs["single_use_code"]:
        # TODO: render image
        custom_log(request, "Invalid one-time code for QR. Referrer: %s" % request.META.get("HTTP_REFERRER"), level="warn")
        return HttpResponseForbidden("Invalid one-time code: unable to show QR")

    # Delete QR nonce to prevent replay.
    request.browser.authenticator_qr_nonce = None
    request.browser.save()

    totp = pyotp.TOTP(request.browser.user.strong_authenticator_secret)
    img = qrcode.make(totp.provisioning_uri(request.browser.user.username+"@futu"))
    stringio = StringIO()
    img.save(stringio)
    stringio.seek(0)
    custom_log(request, "Downloaded Authenticator secret QR code", level="info")
    return HttpResponse(stringio.read(), content_type="image/png")

@protect_view("configure_authenticator", required_level=Browser.L_STRONG)
def configure_authenticator(request):
    """ Google Authenticator configuration view. Only POST requests are allowed. """
    ret = {}
    user = request.browser.user
    if request.method != "POST":
        custom_log(request, "Tried to enter Authenticator configuration view with GET request. Redirecting back. Referer: %s" % request.META.get("HTTP_REFERRER"), level="info")
        return custom_redirect("login_frontend.views.configure_strong", request.GET)

    ret["back_url"] = redir_to_sso(request).url

    regen_secret = True
    otp = request.POST.get("otp_code")
    if otp:
        (status, message) = request.browser.user.validate_authenticator_code(otp)
        if status:
            # Correct code.
            user.strong_configured = True
            user.strong_authenticator_used = True
            user.strong_sms_always = False
            user.save()
            custom_log(request, "Reconfigured Authenticator")
            add_log_entry(request, "Successfully configured Authenticator")
            return redir_to_sso(request)
        else:
            # Incorrect code. Don't regen secret.
            custom_log(request, "Entered invalid OTP during Authenticator configuration")
            add_log_entry(request, "Entered invalid OTP during Authenticator configuration")
            regen_secret = False
            ret["invalid_otp"] = message

    if regen_secret:
        authenticator_secret = user.gen_authenticator()
        ret["authenticator_secret"] = authenticator_secret
        # As new secret was generated and saved, authenticator configuration is no longer valid.
        # Similarly, strong authentication is no longer configured, because authenticator configuration
        # was revoked.
        user.strong_authenticator_used = False
        user.strong_configured = False
        user.save()
        add_log_entry(request, "Regenerated Authenticator code")
        custom_log(request, "Regenerated Authenticator code")

    request.browser.authenticator_qr_nonce = create_browser_uuid()
    ret["authenticator_qr_nonce"] = request.browser.authenticator_qr_nonce
    request.browser.save()

    if request.POST.get("show_manual") == "true":
        ret["show_manual"] = True

    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("configure_authenticator.html", ret, context_instance=RequestContext(request))
    return response

@protect_view("authenticate_with_emergency", required_level=Browser.L_BASIC)
def authenticate_with_emergency(request):
    try:
        codes = EmergencyCodes.objects.get(user=request.browser.user)
    except EmergencyCodes.DoesNotExist:
        # No emergency codes generated. Show error message.
        pass

@require_http_methods(["GET", "POST"])
@ratelimit(rate='15/15s', ratekey='15s', block=True, method=["POST", "GET"], skip_if=is_authenticated)
@protect_view("logoutview", required_level=Browser.L_UNAUTH) # No authentication required to prevent silly sign-in - logout cycle.
def logoutview(request):
    """ Handles logout as well as possible. 

    Only POST requests with valid CSRF token are accepted. In case of
    a GET request, page with logout button is shown.
    """        

    if request.method == 'POST':
        add_log_entry(request, "Signed out")
        custom_log(request, "Signed out")
        logout_keys = ["username", "authenticated", "authentication_level", "login_time", "relogin_time"]
        for keyname in logout_keys:
            try:
                del request.session[keyname]
            except KeyError:
                pass
 
        if request.browser is not None:
            request.browser.logout()
        django_auth.logout(request)
        request.session["logout"] = True
        return custom_redirect("login_frontend.views.indexview", request.GET.dict())
    else:
        ret = {}
        ret["get_params"] = urllib.urlencode(request.GET)
        if request.browser is None:
            ret["not_logged_in"] = True
        elif request.browser.get_auth_level() < Browser.L_BASIC:
            ret["not_logged_in"] = True
        return render_to_response("logout.html", ret, context_instance=RequestContext(request))
