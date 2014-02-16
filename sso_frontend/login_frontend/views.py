from StringIO import StringIO
from django.contrib import auth as django_auth
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
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
from providers import pubtkt_logout
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
            get_params = request.GET.dict()
            if get_params.get("_sso") is None:
                # Avoid redirect loops
                if current_step not in ("firststepauth", "secondstepauth", "authenticate_with_sms", "authenticate_with_password", "authenticate_with_authenticator"):
                    get_params["_sso"] = "internal"
                    get_params["next"] = request.build_absolute_uri()

            browser = request.browser
            if browser is None:
                current_level = Browser.L_UNAUTH
            else:
                current_level = int(browser.get_auth_level())


            if kwargs.get("admin_only", False):
                if not (browser.user and browser.user.is_admin):
                    raise PermissionDenied

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
    ret["remembered"] = request.browser.save_browser


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
    if request.browser is None:
        # No Browser object is initialized. Create one.
        custom_log(request, "No browser object exists. Create a new one. Cookies: %s" % request.COOKIES, level="debug")
        browser = Browser(bid=create_browser_uuid(), bid_public=create_browser_uuid(), bid_session=create_browser_uuid(), ua=request.META.get("HTTP_USER_AGENT"))
        browser.save()
        cookies.extend(browser.get_cookie())
    else:
        custom_log(request, "Browser object exists", level="debug")
        browser = request.browser
        auth_state = browser.get_auth_state()
        if browser.get_auth_state() in (Browser.S_REQUEST_STRONG, ):
            # User is already in strong authentication. Redirect them there.
            custom_log(request, "State: REQUEST_STRONG. Redirecting user", level="debug")
            return custom_redirect("login_frontend.views.secondstepauth", request.GET)
        if browser.get_auth_state() in (Browser.S_AUTHENTICATED, ):
            # User is already authenticated. Redirect back to SSO service.
            custom_log(request, "User is already authenticated. Redirect back to SSO service.", level="debug")
            return redir_to_sso(request)

    if browser.forced_sign_out:
        ret["forced_sign_out"] = True

    if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
        ret["basic_only"] = True
        if not browser.user:
            custom_log(request, "S_REQUEST_BASIC_ONLY was requested, but browser.user does not exist", level="warn")
            messages.warning(request, "Invalid request was encountered. Please sign in again.")
            return custom_redirect("login_frontend.views.indexview", request.GET.dict())

    if request.method == 'POST':
        custom_log(request, "POST request", level="debug")
        form = AuthWithPasswordForm(request.POST)
        if form.is_valid():
            custom_log(request, "Form is valid", level="debug")
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            auth = LdapLogin(username, password, r)
            auth_status = auth.login()
            if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
                 # Only basic authentication was requested. Validate username was not changed.
                 if not (browser.user and username == browser.user.username):
                     custom_log(request, "Username was changed for S_REQUEST_BASIC_ONLY.", level="warn")
                     messages.warning(request, "Invalid request was encountered. Please sign in again.")
                     browser.logout(request)
                     return custom_redirect("login_frontend.views.indexview", request.GET.dict())

            if request.POST.get("my_computer"):
                custom_log(request, "Marked browser as saved", level="info")
                browser.save_browser = True
                browser.save()
            else:
                browser.save_browser = False
                browser.save()

            if auth_status == True:
                    

                # User authenticated successfully. Update AUTH_STATE and AUTH_LEVEL
                browser.forced_sign_out = False
 

                if browser.user is None:
                    custom_log(request, "browser.user is None", level="debug")
                    (user, created) = User.objects.get_or_create(username=auth.username)
                    user.user_tokens = json.dumps(auth.get_auth_tokens())
                    custom_log(request, "User tokens: %s" % user.user_tokens, level="info")
                    user.save()
                    browser.user = user

                request.browser = browser

                add_log_entry(request, "Successfully logged in using username and password", "sign-in")
                custom_log(request, "Successfully logged in using username and password")
                if browser.user.emulate_legacy:
                    custom_log(request, "Emulating legacy SSO", level="info")
                    # This is a special case for emulating legacy system:
                    # - no two-factor authentication
                    # - all logins expire in 12 hours
                    browser.set_auth_level(Browser.L_STRONG)
                    browser.set_auth_state(Browser.S_AUTHENTICATED)
                    browser.save()
                    custom_log(request, "Redirecting back to SSO service", level="info")
                    return redir_to_sso(request)

                # TODO: no further authentication is necessarily needed. Determine these automatically.
                if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
                    # Only basic authentication is required.
                    browser.set_auth_level(Browser.L_STRONG)
                    browser.set_auth_state(Browser.S_AUTHENTICATED)
                else:
                    # Continue to strong authentication
                    browser.set_auth_level(Browser.L_BASIC)
                    browser.set_auth_state(Browser.S_REQUEST_STRONG)
                browser.save()

                return custom_redirect("login_frontend.views.secondstepauth", request.GET)
            else:
                if auth_status == "invalid_credentials":
                    ret["authentication_failed"] = True
                    custom_log(request, "Authentication failed. Invalid credentials", level="warn")
                    add_log_entry(request, "Authentication failed. Invalid credentials", "warning")
                else:
                    ret["message"] = auth_status 
                    custom_log(request, "Authentication failed: %s" % auth_status, level="warn")
                    add_log_entry(request, "Authentication failed: %s" % auth_status, "warning")
    else:
        custom_log(request, "GET request", level="debug")
        form = AuthWithPasswordForm(request.POST)
    ret["form"] = form
    ret["my_computer"] = browser.save_browser

    # Keep GET query parameters in form posts.
    ret["get_params"] = urllib.urlencode(request.GET)
    custom_log(request, "Query parameters: %s" % ret["get_params"], level="debug")
    response = render_to_response("authenticate_with_password.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        custom_log(request, "Setting cookie %s=%s" % (cookie_name, cookie))
        response.set_cookie(cookie_name, **cookie)
    return response


@protect_view("secondstepauth", required_level=Browser.L_BASIC)
def secondstepauth(request):
    """ Determines proper second step authentication method """
    assert request.browser is not None, "Second step authentication requested, but browser is None."
    assert request.browser.user is not None, "Second step authentication requested, but user is not specified."

    custom_log(request, "Second step authentication requested", level="debug")

    get_params = request.GET
    user = request.browser.user

    # If already authenticated with L_STRONG, redirect back to destination
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        custom_log(request, "User is already authenticated. Redirect back to SSO", level="info")
        return redir_to_sso(request)

    if not user.strong_configured:
        # User has not configured any authentication. Go to that pipe.
        custom_log(request, "Strong authentication is not configured. Go to SMS authentication", level="info")
        return custom_redirect("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_sms_always:
        # Strong authentication has been configured, and user has requested to get SMS message.
        custom_log(request, "User has requested SMS authentication.", level="info")
        return custom_redirect("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_authenticator_secret:
        custom_log(request, "Authenticator is properly configured. Redirect.", level="info")
        return custom_redirect("login_frontend.views.authenticate_with_authenticator", get_params)

    custom_log(request, "No proper redirect configured.", level="error")
    return HttpResponse("Second step auth: no proper redirect configured.")

@protect_view("authenticate_with_authenticator", required_level=Browser.L_BASIC)
def authenticate_with_authenticator(request):
    """ Authenticates user with Google Authenticator """

    custom_log(request, "Requested authentication with Authenticator", level="debug")

    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        custom_log(request, "User is already authenticated. Redirect back to SSO", level="info")
        return redir_to_sso(request)

    ret = {}
    user = request.browser.user
    assert user != None, "Browser is authenticated but no User object exists."

    if not user.strong_authenticator_secret:
        # Authenticator is not configured. Redirect back to secondstep main screen
        custom_log(request, "Authenticator is not configured, but user accessed Authenticator view. Redirect back to secondstepauth", level="error")
        return custom_redirect("login_frontend.views.secondstepauth", request.GET)

    if request.method == "POST" and not request.session.test_cookie_worked():
        ret["enable_cookies"] = True

    elif request.method == "POST":
        request.session.delete_test_cookie()

        custom_log(request, "POST request", level="debug")
        form = OTPForm(request.POST)
        if form.is_valid():
            custom_log(request, "Form is valid", level="debug")
            otp = form.cleaned_data["otp"]
            custom_log(request, "Testing OTP code %s at %s" % (form.cleaned_data["otp"], time.time()), level="debug")
            (status, message) = user.validate_authenticator_code(form.cleaned_data["otp"])
            if request.POST.get("my_computer"):
                custom_log(request, "Marked browser as saved", level="info")
                request.browser.save_browser = True
                request.browser.save()

            if not status:
                # If authenticator code did not match, also try latest SMS (if available).
                custom_log(request, "Authenticator code did not match. Testing SMS", level="info")
                status, _ = request.browser.validate_sms(otp)
            if status:
                custom_log(request, "Second-factor authentication with Authenticator succeeded")
                add_log_entry(request, "Second-factor authentication with Authenticator succeeded", "lock")
                # Mark authenticator configuration as valid. User might have configured
                # authenticator but aborted without entering validation code.
                user.strong_authenticator_used = True
                user.save()

                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                custom_log(request, "Redirecting back to SSO provider", level="debug")
                return redir_to_sso(request)
            else:
                custom_log(request, "Incorrect OTP provided: %s" % message, level="warn")
                add_log_entry(request, "Incorrect OTP provided: %s" % message, "warning")
                ret["invalid_otp"] = message
    else:
        custom_log(request, "GET request", level="debug")
        form = OTPForm()


    ret["form"] = form
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser
    request.session.set_test_cookie()

    response = render_to_response("authenticate_with_authenticator.html", ret, context_instance=RequestContext(request))
    return response
       


@protect_view("authenticate_with_sms", required_level=Browser.L_BASIC)
def authenticate_with_sms(request):
    """ Authenticate user with SMS. 
    Accepts Authenticator codes too.
    """
    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.get_auth_level() == Browser.L_STRONG or request.browser.get_auth_state() == Browser.S_AUTHENTICATED:
        custom_log(request, "User is already authenticated. Redirect back to SSO service", level="debug")
        return redir_to_sso(request)

    custom_log(request, "authenticate_with_sms", level="debug")

    user = request.browser.user
    ret = {}
    if not (user.primary_phone or user.secondary_phone):
        # Phone numbers are not available.
        custom_log(request, "No phone number available - unable to authenticate.", level="warning")
        return render_to_response("no_phone_available.html", ret, context_instance=RequestContext(request))

    if not user.strong_configured:
        custom_log(request, "Strong authentication is not configured yet.", level="debug")
        # No strong authentication is configured.
        ret["strong_not_configured"] = True
    if user.primary_phone_changed:
        custom_log(request, "Phone number has changed.", level="debug")
        # Phone number changed. For security reasons...
        ret["primary_phone_changed"] = True

    if request.method == "POST":
        custom_log(request, "POST request", level="debug")
        form = OTPForm(request.POST)
        if form.is_valid():
            custom_log(request, "Form is valid", level="debug")
            otp = form.cleaned_data["otp"]
            status, message = request.browser.validate_sms(otp)
            if request.POST.get("my_computer"):
                custom_log(request, "Marked browser as saved", level="info")
                request.browser.save_browser = True
                request.browser.save()
            if not status:
                # If OTP from SMS did not match, also test for Authenticator OTP.
                custom_log(request, "OTP from SMS did not match, testing Authenticator", level="info")
                (status, _) = request.browser.user.validate_authenticator_code(otp)

            if status:
                # Authentication succeeded.
                custom_log(request, "Second-factor authentication succeeded")
                add_log_entry(request, "Second-factor authentication succeeded", "lock")
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                user.primary_phone_changed = False
                user.save()
                if not user.strong_configured:
                    # Strong authentication is not configured. Go to configuration view.
                    custom_log(request, "User has not configured strong authentication. Redirect to configuration view", level="debug")
                    return custom_redirect("login_frontend.views.configure_strong", request.GET)
                # Redirect back to SSO service
                custom_log(request, "Redirecting back to SSO provider", level="debug")
                return redir_to_sso(request)
            else:
                if message:
                    ret["message"] = message
                    custom_log(request, "OTP login failed: %s" % message, level="warn")
                    add_log_entry(request, "OTP login failed: %s" % message, "warning")
                else:
                    custom_log(request, "Incorrect OTP", level="warn")
                    add_log_entry(request, "Incorrect OTP", "warning")
                    ret["authentication_failed"] = True
    else:
        custom_log(request, "GET request", level="debug")
        form = OTPForm()

    if request.method == "GET" or request.GET.get("regen_sms") or not request.browser.valid_sms_exists():
        custom_log(request, "Generating a new SMS code", level="info")
        sms_text = request.browser.generate_sms_text()
        for phone in (user.primary_phone, user.secondary_phone):
            if phone:
                status = send_sms(phone, sms_text)
                custom_log(request, "Sent OTP to %s" % phone)
                add_log_entry(request, "Sent OTP code to %s" % phone, "info")
                if not status:
                    ret["message"] = "Sending SMS to %s failed." % phone
                    custom_log(request, "Sending SMS to %s failed" % phone, level="warn")
                    add_log_entry(request, "Sending SMS to %s failed" % phone)
            
    ret["expected_sms_id"] = request.browser.sms_code_id
    ret["form"] = form
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser

    response = render_to_response("authenticate_with_sms.html", ret, context_instance=RequestContext(request))
    return response


def js_ping(request, **kwargs):
    ret = {}
    sign_out = False
    if not request.browser:
        # TODO: check whether browser thinks it's still signed in.
        pass
    elif request.browser.forced_sign_out and not request.GET.get("forced_sign_out"):
        # User is not authenticated. If the browser thinks otherwise, fix that.
        ret["not_logged_in"] = True
        ret["redirect_location"] = reverse("login_frontend.views.indexview")+"?forced_sign_out=true"
        sign_out = True

    response = HttpResponse(json.dumps(ret), content_type="application/json")
    if sign_out:
        pubtkt_logout(request, response)
    return response


@protect_view("sessions", required_level=Browser.L_STRONG)
def sessions(request):
    user = request.browser.user
    ret = {}
    if request.method == "POST":
        if request.POST.get("logout"):
            bid_public = request.POST.get("logout")
            if bid_public == "all":
                # Log out all sessions
                custom_log(request, "Requested signing out all sessions", level="info")
                bid_public = [obj.bid_public for obj in Browser.objects.filter(user=user).exclude(bid_public=request.browser.bid_public)]
            else:
                bid_public = [bid_public]

            custom_log(request, "Signing out sessions: %s" % bid_public, level="debug")

            self_logout = False
            for bid in bid_public:
                try:
                    browser_logout = Browser.objects.get(bid_public=bid)
                    if browser_logout.user != user:
                        ret["message"] = "That browser belongs to another user."
                    else:
                        if browser_logout == request.browser:
                            self_logout = True
                        browser_logout.logout()
                        browser_logout.forced_sign_out = True
                        browser_logout.save()
                        custom_log(request, "Signed out browser %s" % browser_logout.bid_public, level="info")
                        add_log_entry(request, "Signed out browser %s" % browser_logout.bid_public, "sign-out")
                        add_log_entry(request, "Signed out by browser %s" % request.browser.bid_public, "sign-out", bid_public=browser_logout.bid_public)
                        messages.success(request, "Signed out browser %s" % browser_logout.get_readable_ua())
                except Browser.DoesNotExist:
                    ret["message"] = "Invalid browser"

            if self_logout:
                get_params = request.GET.dict()
                get_params["logout"] = "on"
                return custom_redirect("login_frontend.views.logoutview", get_params)
            return custom_redirect("login_frontend.views.sessions", request.GET)


    browsers = Browser.objects.filter(user=user)
    sessions = []
    for browser in browsers:
        session = BrowserUsers.objects.get(user=user, browser=browser)
        details = {"session": session, "browser": browser}
        if browser == request.browser:
            details["this_session"] = True
        details["geo"] = get_geoip_string(session.remote_ip)
        details["icons"] = browser.get_ua_icons()

        logins = BrowserLogin.objects.filter(user=user, browser=browser).filter(can_logout=False).filter(signed_out=False).filter(expires_at__gte=timezone.now())
        details["logins"] = logins

        sessions.append(details)

    ret["sessions"] = sessions
    ret["num_sessions"] = len(sessions)
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("sessions.html", ret, context_instance=RequestContext(request))
    return response


@protect_view("view_log", required_level=Browser.L_STRONG)
def view_log(request, **kwargs):
    ret = {}

    browsers = {}
    ret["browsers"] = []
    list_of_browsers = Log.objects.filter(user=request.browser.user).values("bid_public").distinct()
    for item in list_of_browsers:
        try:
            browser_item = Browser.objects.get(bid_public=item["bid_public"])
        except Browser.DoesNotExist:
            continue
        browsers[item["bid_public"]] = browser_item
        ret["browsers"].append(browser_item)

    entries = Log.objects.filter(user=request.browser.user).order_by("-timestamp")
    bid_public = kwargs.get("bid_public")
    if bid_public:
        entries = entries.filter(bid_public=bid_public)
        try:
            ret["this_browser"] = Browser.objects.get(bid_public=bid_public)
        except Browser.DoesNotExist:
            pass

    entries_out = []
    for entry in entries[0:100]:
       browser = browsers.get(entry.bid_public)
       if not browser:
           try:
               browser = Browser.objects.get(bid_public=entry.bid_public)
               browsers[entry.bid_public] = browser
           except Browser.DoesNotExist:
               pass
       entry.browser = browser
       entries_out.append(entry)

    ret["entries"] = entries_out

    response = render_to_response("view_log.html", ret, context_instance=RequestContext(request))
    return response



@protect_view("configure_strong", required_level=Browser.L_STRONG)
def configure_strong(request):
    """ Configuration view for general options. """
    user = request.browser.user
    ret = {}

    if request.method == "POST":
        if request.POST.get("always_sms") == "on":
            add_log_entry(request, "Switched to SMS authentication", "info")
            custom_log(request, "Switched to SMS authentication", level="info")
            user.strong_configured = True
            user.strong_sms_always = True
            user.save()
            messages.success(request, "Switched to SMS authentication")
            return custom_redirect("login_frontend.views.configure_strong", request.GET.dict())
        elif request.POST.get("always_sms") == "off":
            add_log_entry(request, "Switched to Authenticator authentication", "info")
            custom_log(request, "Switched to Authenticator authentication", level="info")
            user.strong_sms_always = False
            user.save()
            messages.success(request, "Default setting changed to Authenticator")
            return custom_redirect("login_frontend.views.configure_strong", request.GET.dict())

    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    back_url = redir_to_sso(request, no_default=True)
    ret["num_sessions"] = Browser.objects.filter(user=user).count()

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
            # Correct OTP.
            user.strong_configured = True
            user.strong_authenticator_used = True
            user.strong_sms_always = False
            user.save()
            custom_log(request, "Reconfigured Authenticator", level="info")
            add_log_entry(request, "Successfully configured Authenticator", "gear")
            messages.success(request, "Successfully configured Authenticator")
            redir = redir_to_sso(request, no_default=True)
            if redir:
                return redir_to_sso(request)
            return custom_redirect("login_frontend.views.configure_strong", request.GET.dict())
        else:
            # Incorrect code. Don't regen secret.
            custom_log(request, "Entered invalid OTP during Authenticator configuration", level="info")
            add_log_entry(request, "Entered invalid OTP during Authenticator configuration", "warning")
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
        add_log_entry(request, "Regenerated Authenticator code", "gear")
        custom_log(request, "Regenerated Authenticator code", level="info")

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
#@protect_view("logoutview", required_level=Browser.L_UNAUTH) # No authentication required to prevent silly sign-in - logout cycle.
def logoutview(request):
    """ Handles logout as well as possible. 

    Only POST requests with valid CSRF token are accepted. In case of
    a GET request, page with logout button is shown.
    """        

    if request.method == 'POST' and request.browser and request.browser.user:
        ret_dict = request.GET.dict()
        ret_dict["logout"] = "on"
        logins = BrowserLogin.objects.filter(user=request.browser.user, browser=request.browser).filter(can_logout=False).filter(signed_out=False)
        active_sessions = []
        for login in logins:
            active_sessions.append({"sso_provider": login.sso_provider, "remote_service": login.remote_service, "expires_at": login.expires_at, "expires_session": login.expires_session, "auth_timestamp": login.auth_timestamp})

        add_log_entry(request, "Signed out", "sign-out")
        custom_log(request, "Signed out")
        logout_keys = ["username", "authenticated", "authentication_level", "login_time", "relogin_time"]
        for keyname in logout_keys:
            try:
                del request.session[keyname]
            except KeyError:
                pass
 
        if request.browser is not None:
            request.browser.logout(request)
        django_auth.logout(request)
        request.session["active_sessions"] = active_sessions
        request.session["logout"] = True
        return custom_redirect("login_frontend.views.logoutview", ret_dict)
    else:
        ret = {}
        if request.GET.get("logout") == "on":
            ret["signed_out"] = True
            ret["active_sessions"] = request.session.get("active_sessions")
            try:
                del request.session["active_sessions"]
            except KeyError:
                pass
        get_params = request.GET.dict()
        try:
            del get_params["logout"]
        except KeyError:
            pass
        ret["get_params"] = urllib.urlencode(get_params)
        if request.browser is None:
            ret["not_logged_in"] = True
        elif request.browser.get_auth_level() < Browser.L_BASIC:
            ret["not_logged_in"] = True
        return render_to_response("logout.html", ret, context_instance=RequestContext(request))
