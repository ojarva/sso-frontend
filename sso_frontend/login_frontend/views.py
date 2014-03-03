#pylint: disable-msg=C0301
"""
Views for SSO service frontend.

This does not include error views (see error_views.py) or admin UI (see admin_frontend module).
"""

from StringIO import StringIO
from cspreporting.models import CSPReport
from django.conf import settings
from django.contrib import auth as django_auth
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseNotFound, Http404
from django.shortcuts import render_to_response
from django.template.loader import render_to_string
from django.template import RequestContext
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods
from login_frontend.forms import OTPForm
if settings.FAKE_TESTING:
    from login_frontend.ldap_stub import LdapLogin
else:
    from login_frontend.ldap_auth import LdapLogin
from login_frontend.models import *
from login_frontend.providers import pubtkt_logout
from login_frontend.send_sms import send_sms
from login_frontend.utils import save_timing_data, get_geoip_string, redirect_with_get_params, redir_to_sso, paginate, get_return_url
from ratelimit.decorators import ratelimit
import datetime
import json
import logging
import math
import os
import pyotp
import qrcode
import redis
import sys
import time
import urllib

log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger("users.%s" % __name__)

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
    method = getattr(user_log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("[%s:%s:%s] %s - %s - %s - %s", filename, lineno, co_name, 
                            remote_addr, username, bid_public, message)


def protect_view(current_step, **main_kwargs):
    """ After this is executed, kwargs["required_level"] is satisfied.
        If not given, Browser.L_STRONG is required.
        Otherwise, user is redirected to appropriate login step.
        This never redirects user to the originating service.
    """

    def redir_view(next_view, resp):
        """ Returns response if current step is not
            the next view - i.e only redirect if view is going to change """
        if current_step == next_view:
            return None
        return resp

    def wrap(inner_func):
        def inner(request, *args, **kwargs):
            required_level = main_kwargs.get("required_level", Browser.L_STRONG)
            get_params = request.GET.dict()
            if get_params.get("_sso") is None:
                # Avoid redirect loops
                if current_step not in ("firststepauth", "secondstepauth", 
                     "authenticate_with_sms", "authenticate_with_password",
                     "authenticate_with_authenticator"):
                    get_params["_sso"] = "internal"
                    get_params["next"] = request.build_absolute_uri()
                    custom_log(request, "Automatically adding internal SSO. next=%s" % get_params["next"], level="debug")

            browser = request.browser
            if browser is None:
                current_level = Browser.L_UNAUTH
            else:
                current_level = int(browser.get_auth_level())

            admin_allowed = True
            if main_kwargs.get("admin_only", False):
                if not (browser and browser.user and browser.user.is_admin):
                    admin_allowed = False

            if current_level >= required_level:
                if not admin_allowed:
                    custom_log(request, "User have no access to admin_only resource %s" % request.path, level="warn")
                    raise PermissionDenied
                # Authentication level is already satisfied
                # Execute requested method.
                return inner_func(request, *args, **kwargs)

            # Authentication level is not satisfied. Determine correct step for next page.
            if browser is None:
                # User is not authenticated. Go to first step.
                custom_log(request, "Browser object does not exist. Go to first step authentication", level="debug")
                return redir_view("firststepauth", redirect_with_get_params('login_frontend.views.firststepauth', get_params))

            if browser.get_auth_state() == Browser.S_REQUEST_STRONG:
                # Login is still valid. Go to second step authentication
                custom_log(request, "Second step authentication requested.", level="debug")
                return redir_view("secondstepauth", redirect_with_get_params("login_frontend.views.secondstepauth", get_params))


            # Requested authentication level is not satisfied, and user is not proceeding to the second step.
            # Start from the beginning.
            custom_log(request, "Requested authentication level is not satisfied. Start from the first step authentication", level="debug")
            return redir_view("firststepauth", redirect_with_get_params("login_frontend.views.firststepauth", get_params))

        return inner
    return wrap

@require_http_methods(["GET", "POST"])
def main_redir(request):
    """ Hack to enable backward compatibility with pubtkt.
    If "back" parameter is specified, forward to pubtkt provider. Otherwise, go to index page
    """
    if request.GET.get("back") != None:
        custom_log(request, "Redirecting to pubtkt provider from main: %s" % request.GET.dict(), level="debug")
        return redirect_with_get_params("login_frontend.providers.pubtkt", request.GET)
    return redirect_with_get_params("login_frontend.views.indexview", request.GET)

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("indexview", required_level=Browser.L_BASIC)
def indexview(request):
    """ Index page: user is redirected
    here if no real destination is available. """

    # TODO: "valid until"
    ret = {}

    if request.method == "POST":
        if request.POST.get("my_computer"):
            save_browser = False
            if request.POST.get("my_computer") == "on":
                save_browser = True
            if request.browser.save_browser != save_browser:
                request.browser.save_browser = save_browser
                request.browser.save()
                if save_browser:
                    custom_log(request, "Marked browser as remembered", level="info")
                    add_user_log(request, "Marked browser as remembered", "eye")
                    messages.info(request, "You're now remembered on this browser")
                else:
                    custom_log(request, "Marked browser as not remembered", level="info")
                    add_user_log(request, "Marked browser as not remembered", "eye-slash")
                    messages.info(request, "You're no longer remembered on this browser")
                return redirect_with_get_params("login_frontend.views.indexview", request.GET.dict())

    ret["username"] = request.browser.user.username
    ret["user"] = request.browser.user
    ret["get_params"] = urllib.urlencode(request.GET)
    auth_level = request.browser.get_auth_level()
    if request.browser.user.emulate_legacy:
        ret["auth_level"] = "emulate_legacy"
        ret["session_expire"] = request.browser.auth_level_valid_until
    elif auth_level == Browser.L_STRONG:
        ret["auth_level"] = "strong"
    elif auth_level == Browser.L_STRONG_SKIPPED:
        ret["auth_level"] = "strong_skipped"
    elif auth_level == Browser.L_BASIC:
        ret["auth_level"] = "basic"
    ret["remembered"] = request.browser.save_browser
    ret["should_timesync"] = request.browser.should_timesync()

    response = render_to_response("login_frontend/indexview.html", ret, context_instance=RequestContext(request))
    return response

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("firststepauth", required_level=Browser.L_UNAUTH)
def firststepauth(request):
    """ Redirects user to appropriate first factor authentication.
    Currently only username/password query """
    return redirect_with_get_params("login_frontend.views.authenticate_with_password", request.GET)

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_password", required_level=Browser.L_UNAUTH)
def authenticate_with_password(request):
    """ Authenticate with username and password """

    ret = {}
    cookies = []
    browser = None

    ret["return_readable"] = get_return_url(request)

    if request.browser is None:
        # No Browser object is initialized. Create one.
        custom_log(request, "1f: No browser object exists. Create a new one. Cookies: %s" % request.COOKIES, level="debug")
        browser = Browser(bid=create_browser_uuid(), bid_public=create_browser_uuid(), bid_session=create_browser_uuid(), ua=request.META.get("HTTP_USER_AGENT"))
        browser.save()
        cookies.extend(browser.get_cookie())
    else:
        custom_log(request, "1f: Browser object exists", level="debug")
        browser = request.browser
        if browser.get_auth_state() == Browser.S_REQUEST_STRONG:
            # User is already in strong authentication. Redirect them there.
            custom_log(request, "1f: State: REQUEST_STRONG. Redirecting user", level="debug")
            return redirect_with_get_params("login_frontend.views.secondstepauth", request.GET)
        if browser.is_authenticated():
            # User is already authenticated. Redirect back to SSO service.
            custom_log(request, "1f: User is already authenticated. Redirect back to SSO service.", level="debug")
            return redir_to_sso(request)

    if browser:
        if browser.forced_sign_out:
            custom_log(request, "1f: Browser was remotely signed out.", level="debug")
            ret["forced_sign_out"] = True

        if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
            ret["basic_only"] = True
            if not browser.user:
                custom_log(request, "1f: S_REQUEST_BASIC_ONLY was requested, but browser.user does not exist", level="warn")
                messages.warning(request, "Invalid request was encountered. Please sign in again.")
                return redirect_with_get_params("login_frontend.views.indexview", request.GET.dict())
            custom_log(request, "1f: S_REQUEST_BASIC_ONLY requested", level="debug")

    if request.method == 'POST':
        custom_log(request, "1f: POST request", level="debug")
        username = request.POST.get("username")
        if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
            # Only basic authentication was requested. Take username from session.
            username = browser.user.username
        password = request.POST.get("password")

        if username and password:
            custom_log(request, "1f: Both username and password exists. username=%s" % username, level="debug")
            auth = LdapLogin(username, password, r)
            auth_status = auth.login()
            if username != auth.username:
                custom_log(request, "1f: mapped username %s to %s" % (username, auth_username), level="debug")
            username = auth.username # mapped from aliases (email address -> username)

            save_browser = False
            if request.POST.get("my_computer"):
                save_browser = True
            if browser.save_browser != save_browser:
                browser.save_browser = save_browser
                browser.save()
                if save_browser:
                    custom_log(request, "1f: Marked browser as remembered", level="info")
                    add_user_log(request, "Marked browser as remembered", "eye")
                else:
                    custom_log(request, "1f: Marked browser as not remembered", level="info")
                    add_user_log(request, "Marked browser as not remembered", "eye-slash")

            if auth_status == True:
                # User signed in, so there's no reason to keep forced_sign_out anymore.
                browser.forced_sign_out = False

                if browser.user is None:
                    custom_log(request, "1f: browser.user is None: %s" % username, level="debug")
                    (user, _) = User.objects.get_or_create(username=username)
                    user.user_tokens = json.dumps(auth.get_auth_tokens())
                    custom_log(request, "User tokens: %s" % user.user_tokens, level="info")
                    user.save()
                    browser.user = user

                request.browser = browser

                custom_log(request, "1f: Successfully logged in using username and password")
                add_user_log(request, "Successfully logged in using username and password", "sign-in")

                if request.POST.get("timing_data"):
                    custom_log(request, "1f: saving timing data", level="debug")
                    timing_data = request.POST.get("timing_data")
                    save_timing_data(request, browser.user, timing_data)

                if browser.user.emulate_legacy:
                    custom_log(request, "1f: Emulating legacy SSO", level="info")
                    # This is a special case for emulating legacy system:
                    # - no two-factor authentication
                    # - all logins expire in 12 hours
                    browser.set_auth_level(Browser.L_STRONG_SKIPPED)
                    browser.set_auth_state(Browser.S_AUTHENTICATED)
                    browser.save()
                    custom_log(request, "1f: Redirecting back to SSO service", level="info")
                    return redir_to_sso(request)

                # TODO: no further authentication is necessarily needed. Determine these automatically.
                if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
                    # Only basic authentication is required.
                    custom_log(request, "1f: only basic authentication was required. Upgrade directly to L_STRONG and S_AUTHENTICATED")
                    browser.set_auth_level(Browser.L_STRONG)
                    browser.set_auth_state(Browser.S_AUTHENTICATED)
                else:
                    # Continue to strong authentication
                    custom_log(request, "1f: set L_BASIC and S_REQUEST_STRONG")
                    browser.set_auth_level(Browser.L_BASIC)
                    browser.set_auth_state(Browser.S_REQUEST_STRONG)
                browser.save()

                return redirect_with_get_params("login_frontend.views.secondstepauth", request.GET)
            else:
                if auth_status == "invalid_credentials":
                    ret["authentication_failed"] = True
                    custom_log(request, "1f: Authentication failed. Invalid credentials", level="warn")
                    add_user_log(request, "Authentication failed. Invalid credentials", "warning")
                elif auth_status == "server_down":
                    messages.warning(request, "Unable to connect user directory (LDAP). Could not proceed with authentication. Please try again later, and/or contact IT team.")
                    custom_log(request, "1f: LDAP server is down.", level="error")
                else:
                    ret["message"] = auth_status 
                    custom_log(request, "1f: Authentication failed: %s" % auth_status, level="warn")
                    add_user_log(request, "Authentication failed: %s" % auth_status, "warning")
        else:
            custom_log(request, "1f: Either username or password is missing.", level="warn")
            messages.warning(request, "Please enter both username and password.")
    else:
        custom_log(request, "1f: GET request", level="debug")
    if browser:
        ret["my_computer"] = browser.save_browser

    # Keep GET query parameters in form posts.
    ret["get_params"] = urllib.urlencode(request.GET)
    custom_log(request, "1f: Query parameters: %s" % ret["get_params"], level="debug")
    response = render_to_response("login_frontend/authenticate_with_password.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        custom_log(request, "Setting cookie %s=%s" % (cookie_name, cookie))
        response.set_cookie(cookie_name, **cookie)
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("secondstepauth", required_level=Browser.L_BASIC)
def secondstepauth(request):
    """ Determines proper second step authentication method """
    assert request.browser is not None, "Second step authentication requested, but browser is None."
    assert request.browser.user is not None, "Second step authentication requested, but user is not specified."

    custom_log(request, "2f: Second step authentication requested. Parameters: %s" % request.GET.dict(), level="debug")

    get_params = request.GET
    user = request.browser.user

    # If already authenticated with L_STRONG, redirect back to destination
    if request.browser.is_authenticated():
        custom_log(request, "2f: User is already authenticated. Redirect back to SSO", level="info")
        return redir_to_sso(request)

    if not user.strong_configured:
        # User has not configured any authentication. Go to that pipe.
        custom_log(request, "2f: Strong authentication is not configured. Go to SMS authentication", level="info")
        return redirect_with_get_params("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_sms_always:
        # Strong authentication has been configured, and user has requested to get SMS message.
        custom_log(request, "2f: User has requested SMS authentication.", level="info")
        return redirect_with_get_params("login_frontend.views.authenticate_with_sms", get_params)

    if user.strong_authenticator_secret:
        custom_log(request, "2f: Authenticator is properly configured. Redirect.", level="info")
        return redirect_with_get_params("login_frontend.views.authenticate_with_authenticator", get_params)

    custom_log(request, "2f: No proper redirect configured.", level="error")
    return HttpResponse("Second step auth: no proper redirect configured.")

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
# This method should not protected with protect_view. In this case, it is important to show specific error messages.
def authenticate_with_url(request, **kwargs):
    """ Authenticates user with URL sent via SMS """
    def sid_cleanup(sid):
        keys = ["params", "user", "bid"]
        for k in keys:
            r.delete("urlauth-%s-%s" % (k, sid))

    template_name = "login_frontend/authenticate_with_url.html"
    sid = kwargs.get("sid")
    ret = {}
    if not hasattr(request, "browser") or not request.browser or not request.browser.user:
        custom_log(request, "2f-url: No browser object / no signed-in user", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    if not r.exists("urlauth-params-%s" % sid):
        custom_log(request, "2f-url: sid does not exist, or it expired.", level="warn")
        ret["invalid_sid"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    username = r.get("urlauth-user-%s" % sid)
    if username != request.browser.user.username:
        custom_log(request, "2f-url: Tried to access SID that belongs to another user.", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    bid_public = r.get("urlauth-bid-%s" % sid)
    if bid_public != request.browser.bid_public:
        custom_log(request, "2f-url: Tried to access SID with wrong browser. Probably the phone opens SMS links to different browser, or it was actually another phone.", level="warn")
        ret["wrong_browser"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    get_params = r.get("urlauth-params-%s" % sid)
    try:
        get_params_dict = json.loads(get_params)
    except (ValueError, EOFError):
        custom_log(request, "2f-url: Invalid get_params json from redis", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    if request.browser.is_authenticated():
        custom_log(request, "2f-url: User is already signed in. Redirect to secondstepauth: %s" % get_params, level="info")
        sid_cleanup(sid)
        request.browser.revoke_sms()
        return redirect_with_get_params("login_frontend.views.secondstepauth", get_params_dict)

    if not request.browser.get_auth_level() >= Browser.L_BASIC or not request.browser.get_auth_state() == Browser.S_REQUEST_STRONG:
        custom_log(request, "2f-url: Browser is in wrong authentication state", level="warn")
        ret["invalid_auth_state"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    # Everything is fine:
    # - sid is valid
    # - browser matches
    # - user is authenticated
    # set authentication state and redirect through secondstepauth.
    # TODO: determine these automatically
    request.browser.set_auth_level(Browser.L_STRONG)
    request.browser.set_auth_state(Browser.S_AUTHENTICATED)
    request.browser.save()
    sid_cleanup(sid)
    request.browser.revoke_sms()
    custom_log(request, "2f-url: Successfully authenticated with URL. Redirecting to secondstepauth", level="info")
    add_user_log(request, "Successfully authenticated with URL.", "lock")
    return redirect_with_get_params("login_frontend.views.secondstepauth", get_params_dict)


@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_authenticator", required_level=Browser.L_BASIC)
def authenticate_with_authenticator(request):
    """ Authenticates user with Google Authenticator """

    custom_log(request, "2f-auth: Requested authentication with Authenticator", level="debug")

    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.is_authenticated():
        custom_log(request, "2f-auth: User is already authenticated. Redirect back to SSO", level="info")
        return redir_to_sso(request)

    ret = {}
    user = request.browser.user
    assert user != None, "Browser is authenticated but no User object exists."
    ret["return_readable"] = get_return_url(request)

    skips_available = user.strong_skips_available
    ret["skips_available"] = skips_available

    if not user.strong_authenticator_secret:
        # Authenticator is not configured. Redirect back to secondstep main screen
        custom_log(request, "2f-auth: Authenticator is not configured, but user accessed Authenticator view. Redirect back to secondstepauth", level="error")
        messages.warning(request, "You tried to authenticate with Authenticator. However, according to our records, you don't have it configured. Please sign in and go to settings to do that.")
        return redirect_with_get_params("login_frontend.views.secondstepauth", request.GET)

    if not user.strong_authenticator_used:
        custom_log(request, "2f-auth: Authenticator has not been used. Generated at %s" % user.strong_authenticator_generated_at, level="debug")
        ret["authenticator_not_used"] = True
        ret["authenticator_generated"] = user.strong_authenticator_generated_at

    if request.method == "POST" and request.POST.get("skip"):
        if skips_available > 0:
            user.strong_skips_available -= 1
            user.save()
            add_user_log(request, "Skipped strong authentication: %s left" % user.strong_skips_available, "meh-o")
            custom_log(request, "2f-auth: Skipped strong authentication: %s left" % user.strong_skips_available)
            # TODO: determine the levels automatically.
            request.browser.set_auth_level(Browser.L_STRONG_SKIPPED)
            request.browser.set_auth_state(Browser.S_AUTHENTICATED)
            request.browser.set_auth_level_valid_until = timezone.now() + datetime.timedelta(hours=12)
            request.browser.save()
            custom_log(request, "2f-auth: Redirecting back to SSO provider", level="debug")
            return redir_to_sso(request)
        else:
            messages.warning(request, "You can't skip strong authentication anymore.")
            custom_log(request, "2f-auth: Tried to skip strong authentication with no skips available", level="warn")

    form = OTPForm()
    if request.method == "POST" and not request.session.test_cookie_worked():
        custom_log(request, "2f-auth: cookies do not work properly", level="warn")
        ret["enable_cookies"] = True

    elif request.method == "POST":
        request.session.delete_test_cookie()

        custom_log(request, "2f-auth: POST request", level="debug")
        form = OTPForm(request.POST)
        if form.is_valid():
            custom_log(request, "2f-auth: Form is valid", level="debug")
            otp = form.cleaned_data["otp"]
            custom_log(request, "2f-auth: Testing OTP code %s at %s" % (otp, time.time()), level="debug")
            (status, message) = user.validate_authenticator_code(otp, request)

            save_browser = False
            if request.POST.get("my_computer"):
                save_browser = True
            if request.browser.save_browser != save_browser:
                request.browser.save_browser = save_browser
                request.browser.save()
                if save_browser:
                    custom_log(request, "2f-auth: Marked browser as remembered", level="info")
                    add_user_log(request, "Marked browser as remembered", "eye")
                else:
                    custom_log(request, "2f-auth: Marked browser as not remembered", level="info")
                    add_user_log(request, "Marked browser as not remembered", "eye-slash")

            if not status:
                # If authenticator code did not match, also try latest SMS (if available).
                custom_log(request, "2f-auth: Authenticator code did not match. Testing SMS", level="info")
                status, _ = request.browser.validate_sms(otp)
            if status:

                custom_log(request, "2f-auth: Second-factor authentication with Authenticator succeeded")
                add_user_log(request, "Second-factor authentication with Authenticator succeeded", "lock")
                # Mark authenticator configuration as valid. User might have configured
                # authenticator but aborted without entering validation code.
                user.strong_authenticator_used = True
                user.strong_configured = True
                user.save()

                if request.POST.get("timing_data"):
                    custom_log(request, "2f-auth: Saving timing data", level="debug")
                    timing_data = request.POST.get("timing_data")
                    save_timing_data(request, user, timing_data)


                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                custom_log(request, "2f-auth: Redirecting back to SSO provider", level="debug")
                return redir_to_sso(request)
            else:
                custom_log(request, "2f-auth: Incorrect Authenticator OTP provided: %s" % message, level="warn")
                add_user_log(request, "Incorrect Authenticator OTP provided: %s" % message, "warning")
                ret["invalid_otp"] = message
    else:
        custom_log(request, "2f-auth: GET request", level="debug")
        form = OTPForm()


    ret["form"] = form
    ret["user"] = user
    ret["authenticator_id"] = user.get_authenticator_id()
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser
    ret["should_timesync"] = request.browser.should_timesync()
    request.session.set_test_cookie()

    response = render_to_response("login_frontend/authenticate_with_authenticator.html", ret, context_instance=RequestContext(request))
    return response
       


@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_sms", required_level=Browser.L_BASIC)
def authenticate_with_sms(request):
    """ Authenticate user with SMS. 
    Accepts Authenticator codes too.
    """
    # If already authenticated with L_STRONG, redirect back to SSO / frontpage
    if request.browser.is_authenticated():
        custom_log(request, "2f-sms: User is already authenticated. Redirect back to SSO service", level="debug")
        return redir_to_sso(request)

    custom_log(request, "2f-sms: authenticate_with_sms", level="debug")

    user = request.browser.user
    ret = {}
    if not (user.primary_phone or user.secondary_phone):
        # Phone numbers are not available.
        custom_log(request, "2f-sms: No phone number available - unable to authenticate.", level="error")
        ret["should_timesync"] = request.browser.should_timesync()
        return render_to_response("login_frontend/no_phone_available.html", ret, context_instance=RequestContext(request))

    skips_available = user.strong_skips_available
    ret["skips_available"] = skips_available
    ret["return_readable"] = get_return_url(request)

    if request.method == "POST" and request.POST.get("skip"):
        if skips_available > 0:
            user.strong_skips_available -= 1
            user.save()
            add_user_log(request, "Skipped strong authentication: %s left" % user.strong_skips_available, "meh-o")
            custom_log(request, "2f-sms: Skipped strong authentication: %s left" % user.strong_skips_available)
            # TODO: determine the levels automatically.
            request.browser.set_auth_level(Browser.L_STRONG)
            request.browser.set_auth_state(Browser.S_AUTHENTICATED)
            request.browser.set_auth_level_valid_until = timezone.now() + datetime.timedelta(hours=12)
            request.browser.save()
            custom_log(request, "2f-sms: Redirecting back to SSO provider", level="debug")
            return redir_to_sso(request)
        else:
            messages.warning(request, "You can't skip strong authentication anymore.")
            custom_log(request, "2f-sms: Tried to skip strong authentication with no skips available", level="warn")

    if user.strong_configured:
        if user.strong_authenticator_secret:
            ret["can_use_authenticator"] = True
            if not user.strong_authenticator_used:
                ret["authenticator_generated"] = True
    else:
        custom_log(request, "2f-sms: Strong authentication is not configured yet.", level="debug")
        # No strong authentication is configured.
        ret["strong_not_configured"] = True
        if user.strong_authenticator_secret:
            ret["authenticator_generated"] = True
            ret["can_use_authenticator"] = True


    if user.primary_phone_changed:
        custom_log(request, "2f-sms: Phone number has changed.", level="debug")
        # Phone number changed. For security reasons...
        ret["primary_phone_changed"] = True

    if request.method == "POST":
        custom_log(request, "2f-sms: POST request", level="debug")
        form = OTPForm(request.POST)
        if form.is_valid():
            custom_log(request, "2f-sms: Form is valid", level="debug")
            otp = form.cleaned_data["otp"]
            status, message = request.browser.validate_sms(otp)

            save_browser = False
            if request.POST.get("my_computer"):
                save_browser = True
            if request.browser.save_browser != save_browser:
                request.browser.save_browser = save_browser
                request.browser.save()
                if save_browser:
                    custom_log(request, "2f-sms: Marked browser as remembered", level="info")
                    add_user_log(request, "Marked browser as remembered", "eye")
                else:
                    custom_log(request, "2f-sms: Marked browser as not remembered", level="info")
                    add_user_log(request, "Marked browser as not remembered", "eye-slash")

            if not status:
                # If OTP from SMS did not match, also test for Authenticator OTP.
                custom_log(request, "2f-sms: OTP from SMS did not match, testing Authenticator", level="info")
                (status, _) = request.browser.user.validate_authenticator_code(otp, request)

            if status:
                # Authentication succeeded.
                custom_log(request, "2f-sms: Second-factor authentication with SMS succeeded")
                add_user_log(request, "Second-factor authentication with SMS succeeded", "lock")
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                user.primary_phone_changed = False
                user.save()

                if request.POST.get("timing_data"):
                    custom_log(request, "2f-sms: Saved timing data", level="debug")
                    timing_data = request.POST.get("timing_data")
                    save_timing_data(request, user, timing_data)


                if not user.strong_configured:
                    # Strong authentication is not configured. Go to configuration view.
                    custom_log(request, "2f-sms: User has not configured strong authentication. Redirect to configuration view", level="info")
                    return redirect_with_get_params("login_frontend.views.configure_strong", request.GET)
                # Redirect back to SSO service
                custom_log(request, "2f-sms: Redirecting back to SSO provider", level="debug")
                return redir_to_sso(request)
            else:
                if message:
                    ret["message"] = message
                    custom_log(request, "2f-sms: SMS OTP login failed: %s" % message, level="warn")
                    add_user_log(request, "SMS OTP login failed: %s" % message, "warning")
                else:
                    custom_log(request, "2f-sms: Incorrect SMS OTP", level="warn")
                    add_user_log(request, "Incorrect SMS OTP", "warning")
                    ret["authentication_failed"] = True
        else:
            messages.warning(request, "Invalid input")
    else:
        custom_log(request, "2f-sms: GET request", level="debug")
        form = OTPForm()

    if request.method == "GET" or request.GET.get("regen_sms") or not request.browser.valid_sms_exists():
        custom_log(request, "2f-sms: Generating a new SMS code", level="info")
        sms_text = request.browser.generate_sms_text(request=request)
        for phone in (user.primary_phone, user.secondary_phone):
            if phone:
                status = send_sms(phone, sms_text)
                if not status:
                    messages.warning(request, "Sending SMS to %s failed." % phone)
                    custom_log(request, "2f-sms: Sending SMS to %s failed" % phone, level="warn")
                    add_user_log(request, "Sending SMS to %s failed" % phone)
                else:
                    custom_log(request, "2f-sms: Sent OTP to %s" % phone)
                    add_user_log(request, "Sent OTP code to %s" % phone, "info")
                    phone_redacted = "%s...%s" % (phone[0:6], phone[-4:])
                    messages.info(request, mark_safe("Sent SMS to <span class='tooltip-link' title='This is redacted to protect your privacy'>%s</span>" % phone_redacted))

    ret["sms_valid_until"] = request.browser.sms_code_generated_at + datetime.timedelta(seconds=900)
    ret["expected_sms_id"] = request.browser.sms_code_id
    ret["form"] = form
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser
    ret["should_timesync"] = request.browser.should_timesync()

    response = render_to_response("login_frontend/authenticate_with_sms.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET"]) 
def js_ping(request, **kwargs):
    """ Handles time browser queries, and updates browser status when required. """
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

@require_http_methods(["GET"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
def get_pubkey(request, **kwargs):
    service = kwargs.get("service")
    if service == "pubtkt":
        filename = settings.PUBTKT_PUBKEY
    elif service == "saml":
        filename = settings.SAML_PUBKEY
    else:
        raise Http404
    response = HttpResponse(open(filename).read(), content_type="application/x-x509-ca-cert")
    return response


@require_http_methods(["GET"])
def timesync(request, **kwargs):
    """ Calculates difference between server and client timestamps """
    ret = {}
    browser_random = kwargs.get("browser_random")
    redis_id = browser_random

    if not "browser_timezone" in kwargs:
        return render_to_response("login_frontend/timesync.html", {}, context_instance=RequestContext(request))

    browser = None
    if hasattr(request, "browser") and request.browser:
        browser = request.browser
        redis_id = browser.bid_public

    browser_timezone = kwargs.get("browser_timezone")
    browser_time = kwargs.get("browser_time")
    try:
        browser_time = int(browser_time)
    except ValueError:
        browser_time = None
    server_time = kwargs.get("last_server_time")
    recv_time = int(time.time() * 1000)

    def report():
        browser_times = []
        recv_times = []
        while True:
            val = r.lpop(r_k+"browser_time")
            if val is None:
                break
            browser_times.append(int(val))
            val = r.lpop(r_k+"recv_time")
            recv_times.append(int(val))
        if len(recv_times) < 2:
            ret["no_values"] = True
            return
        best_sync = None
        smallest_rtt = None
        errors = []
        for i, _ in enumerate(browser_times):
            if i == 0:
                continue
            bt = browser_times[i]
            rt = recv_times[i]
            rtt = (recv_times[i] - recv_times[i-1]) / 2
            clock_off = rt - bt - rtt
            errors.append(clock_off)
            if smallest_rtt is None or rtt < smallest_rtt:
                best_sync = clock_off
                smallest_rtt = rtt
        def avg(d): return float(sum(d)) / len(d)
        avg_err = avg(errors)
        variance = map(lambda x: (x - avg_err)**2, errors)
        ret["errors_std"] = math.sqrt(avg(variance))
        ret["errors"] = errors
        ret["best_sync"] = best_sync
        ret["report"] = render_to_string("login_frontend/snippets/timesync_results.html", {"best_sync": round(best_sync, 2), "std": round(ret["errors_std"], 2), "meaningful": abs(best_sync) > ret["errors_std"]})
        if browser:
            BrowserTime.objects.create(browser=browser, timezone=browser_timezone, time_diff=best_sync, measurement_error=ret["errors_std"])
        custom_log(request, "Browser timesync: %s ms with +-%s error. bt: %s; rt: %s" % (best_sync, ret["errors_std"], browser_times, recv_times), level="info")

    r_k = "timesync-%s-" % redis_id
    r.rpush(r_k+"browser_time", browser_time)
    r.rpush(r_k+"recv_time", recv_time)
    r.expire(r_k+"browser_time", 30)
    r.expire(r_k+"recv_time", 30)

    if kwargs.get("command") == "results":
        report()

    ret["browser_time"] = float(browser_time)
    ret["server_time"] = int(time.time() * 1000)
    response = HttpResponse(json.dumps(ret), content_type="application/json")
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("sessions", required_level=Browser.L_STRONG)
def sessions(request):
    """ Shows sessions to the user. """
    user = request.browser.user
    ret = {}
    if request.method == "POST":
        if request.POST.get("logout"):
            bid_public = request.POST.get("logout")
            if bid_public == "all":
                # Log out all sessions
                custom_log(request, "sessions: user requested signing out all sessions", level="info")
                bid_public = [obj.bid_public for obj in Browser.objects.filter(user=user).exclude(bid_public=request.browser.bid_public)]
            else:
                bid_public = [bid_public]

            custom_log(request, "sessions: signing out sessions: %s" % bid_public, level="debug")

            self_logout = False
            for bid in bid_public:
                try:
                    browser_logout = Browser.objects.get(bid_public=bid)
                    if browser_logout.user != user:
                        custom_log(request, "sessions: Tried to sign out browser that belongs to another user: %s" % bid, level="warn")
                        ret["message"] = "That browser belongs to another user."
                    else:
                        if browser_logout == request.browser:
                            custom_log(request, "sessions: signing out current browser", level="info")
                            self_logout = True
                        browser_logout.logout()
                        browser_logout.forced_sign_out = True
                        browser_logout.save()
                        custom_log(request, "sessions: Signed out browser %s" % browser_logout.bid_public, level="info")
                        add_user_log(request, "Signed out browser %s" % browser_logout.bid_public, "sign-out")
                        add_user_log(request, "Signed out from browser %s" % request.browser.bid_public, "sign-out", bid_public=browser_logout.bid_public)
                        messages.success(request, "Signed out browser %s" % browser_logout.get_readable_ua())
                except Browser.DoesNotExist:
                    ret["message"] = "Invalid browser"

            if self_logout:
                get_params = request.GET.dict()
                get_params["logout"] = "on"
                return redirect_with_get_params("login_frontend.views.logoutview", get_params)
            return redirect_with_get_params("login_frontend.views.sessions", request.GET)


    browsers = Browser.objects.filter(user=user)
    sessions = []
    for browser in browsers:
        session = BrowserUsers.objects.get(user=user, browser=browser)
        details = {"session": session, "browser": browser}
        if browser == request.browser:
            details["this_session"] = True
        details["geo"] = get_geoip_string(session.remote_ip)
        details["icons"] = browser.get_ua_icons()

        try:
            details["p0f"] = BrowserP0f.objects.filter(browser=browser).latest()
        except BrowserP0f.DoesNotExist:
            pass

        try:
            details["timesync"] = BrowserTime.objects.filter(browser=browser).latest()
        except BrowserTime.DoesNotExist:
            pass

        logins = BrowserLogin.objects.filter(user=user, browser=browser).filter(can_logout=False).filter(signed_out=False).filter(Q(expires_at__gte=timezone.now()) | Q(expires_at=None))
        details["logins"] = logins

        sessions.append(details)
    try:
        sessions.sort(key=lambda item:item.get("session").last_seen, reverse=True)
    except Exception, e:
        # In certain cases, session.last_seen is None.
        custom_log(request, "Unable to sort sessions: %s" % e, level="error")
    ret["sessions"] = sessions
    ret["num_sessions"] = len(sessions)
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["should_timesync"] = request.browser.should_timesync()
    response = render_to_response("login_frontend/sessions.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("view_log", required_level=Browser.L_STRONG)
def view_log(request, **kwargs):
    """ Shows log entries to the user """
    ret = {}

    browsers = {}
    ret["browsers"] = []
    list_of_browsers = Log.objects.filter(user=request.browser.user).order_by("bid_public").values("bid_public").distinct()
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

    entries = paginate(request, entries)

    for entry in entries:
        browser = browsers.get(entry.bid_public)
        if not browser:
            try:
                browser = Browser.objects.get(bid_public=entry.bid_public)
                browsers[entry.bid_public] = browser
            except Browser.DoesNotExist:
                pass
        entry.browser = browser

    ret["entries"] = entries

    response = render_to_response("login_frontend/view_log.html", ret, context_instance=RequestContext(request))
    return response



@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("configure_strong", required_level=Browser.L_STRONG)
def configure_strong(request):
    """ Configuration view for general options. """
    user = request.browser.user
    ret = {}

    if request.method == "POST":
        if request.POST.get("always_sms") == "on":
            add_user_log(request, "Switched to SMS authentication", "info")
            custom_log(request, "cstrong: Switched to SMS authentication", level="info")
            user.strong_configured = True
            user.strong_sms_always = True
            user.strong_skips_available = 0
            user.save()
            messages.success(request, "Switched to SMS authentication")
            return redirect_with_get_params("login_frontend.views.configure_strong", request.GET.dict())
        elif request.POST.get("always_sms") == "off":
            add_user_log(request, "Switched to Authenticator authentication", "info")
            custom_log(request, "cstrong: Switched to Authenticator authentication", level="info")
            # This is only visible when Authenticator is already generated. If it was not generated,
            # user can click to "Use SMS instead"
            user.strong_configured = True
            user.strong_sms_always = False
            user.strong_skips_available = 0
            user.save()
            messages.success(request, "Default setting changed to Authenticator")
            return redirect_with_get_params("login_frontend.views.configure_strong", request.GET.dict())

    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    back_url = redir_to_sso(request, no_default=True)
    ret["num_sessions"] = Browser.objects.filter(user=user).count()
    ret["csp_violations"] = CSPReport.objects.filter(username=user.username).count()
    ret["authenticator_id"] = user.get_authenticator_id()

    if back_url:
        ret["back_url"] = back_url.url
    response = render_to_response("login_frontend/configure_strong.html", ret, context_instance=RequestContext(request))
    return response

@require_http_methods(["GET"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("get_authenticator_qr", required_level=Browser.L_STRONG)
def get_authenticator_qr(request, **kwargs):
    """ Outputs QR code for Authenticator. Uses single_use_code to prevent
    reloading / linking. """
    if not request.browser.authenticator_qr_nonce == kwargs["single_use_code"]:
        custom_log(request, "qr: Invalid one-time code for QR. Referrer: %s" % request.META.get("HTTP_REFERRER"), level="warn")
        return HttpResponseForbidden(open(settings.PROJECT_ROOT + "/static/img/invalid_nonce.png").read(), mimetype="image/png")

    if not request.browser.user.strong_authenticator_secret:
        custom_log(request, "qr: Valid qr_nonce, but authenticator_secret is None", level="error")
        return HttpResponseForbidden(open(settings.PROJECT_ROOT + "/static/img/valid_nonce_no_secret.png").read(), mimetype="image/png")

    # Delete QR nonce to prevent replay.
    request.browser.authenticator_qr_nonce = None
    request.browser.save()

    totp = pyotp.TOTP(request.browser.user.strong_authenticator_secret)
    img = qrcode.make(totp.provisioning_uri(request.browser.user.strong_authenticator_id))
    stringio = StringIO()
    img.save(stringio)
    stringio.seek(0)
    custom_log(request, "qr: Downloaded Authenticator secret QR code", level="info")
    return HttpResponse(stringio.read(), content_type="image/png")

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("configure_authenticator", required_level=Browser.L_STRONG)
def configure_authenticator(request):
    """ Google Authenticator configuration view. Only POST requests are allowed. """
    ret = {}
    user = request.browser.user
    if request.method != "POST":
        custom_log(request, "cauth: Tried to enter Authenticator configuration view with GET request. Redirecting back. Referer: %s" % request.META.get("HTTP_REFERRER"), level="info")
        messages.info(request, "You can't access configuration page directly. Please click a link below to configure Authenticator.")
        return redirect_with_get_params("login_frontend.views.configure_strong", request.GET)

    ret["back_url"] = redir_to_sso(request).url

    regen_secret = True
    otp = request.POST.get("otp_code")
    if otp:
        (status, message) = request.browser.user.validate_authenticator_code(otp, request)
        if status:
            # Correct OTP.
            user.strong_configured = True
            user.strong_authenticator_used = True
            user.strong_sms_always = False
            user.strong_skips_available = 0
            user.save()
            custom_log(request, "cauth: Reconfigured Authenticator", level="info")
            add_user_log(request, "Successfully configured Authenticator", "gear")
            messages.success(request, "Successfully configured Authenticator")
            redir = redir_to_sso(request, no_default=True)
            if redir:
                return redir_to_sso(request)
            return redirect_with_get_params("login_frontend.views.configure_strong", request.GET.dict())
        else:
            # Incorrect code. Don't regen secret.
            custom_log(request, "cauth: Entered invalid OTP during Authenticator configuration", level="info")
            add_user_log(request, "Entered invalid OTP during Authenticator configuration", "warning")
            regen_secret = False
            ret["invalid_otp"] = message
            messages.warning(request, "Invalid one-time password. Please scroll down to try again.")

    if regen_secret:
        authenticator_secret = user.gen_authenticator()
        # As new secret was generated and saved, authenticator configuration is no longer valid.
        # Similarly, strong authentication is no longer configured, because authenticator configuration
        # was revoked.
        user.strong_authenticator_used = False
        user.strong_configured = False
        user.save()
        add_user_log(request, "Regenerated Authenticator code", "gear")
        custom_log(request, "cauth: Regenerated Authenticator code. Set authenticator_used=False, strong_configured=False", level="info")

    ret["authenticator_secret"] = user.strong_authenticator_secret
    ret["authenticator_id"] = user.strong_authenticator_id

    request.browser.authenticator_qr_nonce = create_browser_uuid()
    ret["authenticator_qr_nonce"] = request.browser.authenticator_qr_nonce
    request.browser.save()

    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("login_frontend/configure_authenticator.html", ret, context_instance=RequestContext(request))
    return response

@require_http_methods(["GET", "POST"])
@ratelimit(rate='12/2s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_emergency", required_level=Browser.L_BASIC)
def authenticate_with_emergency(request):
    """ TODO: emergency code authentication """
    try:
        codes = EmergencyCodes.objects.get(user=request.browser.user)
    except EmergencyCodes.DoesNotExist:
        # No emergency codes generated. Show error message.
        pass

@require_http_methods(["GET", "POST"])
def logoutview(request):
    """ Handles logout as well as possible. 

    Only POST requests with valid CSRF token are accepted. In case of
    a GET request, page with logout button is shown.
    """        

    if request.method == 'POST' and hasattr(request, "browser") and request.browser and request.browser.user:
        ret_dict = request.GET.dict()
        ret_dict["logout"] = "on"
        logins = BrowserLogin.objects.filter(user=request.browser.user, browser=request.browser).filter(can_logout=False).filter(signed_out=False).filter(Q(expires_at__gte=timezone.now()) | Q(expires_at=None))
        active_sessions = []
        for login in logins:
            active_sessions.append({"sso_provider": login.sso_provider, "remote_service": login.remote_service, "expires_at": login.expires_at, "expires_session": login.expires_session, "auth_timestamp": login.auth_timestamp})

        add_user_log(request, "Signed out", "sign-out")
        custom_log(request, "Signed out")
        logout_keys = ["username", "authenticated", "authentication_level", "login_time", "relogin_time"]
        for keyname in logout_keys:
            try:
                del request.session[keyname]
            except KeyError:
                pass
 
        request.browser.logout(request)
        django_auth.logout(request)
        request.session["active_sessions"] = active_sessions
        request.session["logout"] = True
        return redirect_with_get_params("login_frontend.views.logoutview", ret_dict)
    else:
        ret = {}
        if request.GET.get("logout") == "on":
            ret["signed_out"] = True
            active_sessions = request.session.get("active_sessions")
            if len(active_sessions) > 0:
                custom_log(request, "logout: active sessions: %s" % active_sessions, level="info")
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
        if request.browser:
            ret["should_timesync"] = request.browser.should_timesync()
        return render_to_response("login_frontend/logout.html", ret, context_instance=RequestContext(request))
