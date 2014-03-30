#pylint: disable-msg=C0301
"""
Views for SSO service frontend.

This does not include error views (see error_views.py) or admin UI (see admin_frontend module).
"""

from django.conf import settings
from django.contrib import auth as django_auth
from django.contrib import messages
from django.core.cache import get_cache
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods
from django_statsd.clients import statsd as sd
from login_frontend.emails import new_device_notify, emergency_used_notify
from login_frontend.models import *
from login_frontend.send_sms import send_sms
from login_frontend.utils import save_timing_data, redirect_with_get_params, redir_to_sso, map_username
from ratelimit.decorators import ratelimit
from ratelimit.helpers import is_ratelimited
import datetime
import json
import logging
import os
import re
import redis
import sys
import time
import urllib

if settings.FAKE_TESTING:
    from login_frontend.ldap_stub import LdapLogin
else:
    from login_frontend.ldap_auth import LdapLogin

dcache = get_cache("default")
ucache = get_cache("user_mapping")
bcache = get_cache("browsers")
user_cache = get_cache("users")


log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger("users.%s" % __name__)

@sd.timer("login_frontend.authentication_views.custom_log")
def custom_log(request, message, **kwargs):
    """ Automatically logs username, remote IP and bid_public """
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
    remote_addr = request.remote_ip
    bid_public = username = ""
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("[%s:%s:%s] %s - %s - %s - %s", filename, lineno, co_name,
                            remote_addr, username, bid_public, message)

INCLUDE_PARAMS_NEXT = ("saml_id", )

@sd.timer("login_frontend.authentication_views.protect_view")
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
                     "authenticate_with_authenticator", "authenticate_with_emergency"):
                    get_params["_sso"] = "internal"
                    included_get_params = {}
                    for p in INCLUDE_PARAMS_NEXT:
                        if p in get_params:
                            included_get_params[p] = get_params[p]
                            del get_params[p]
                    if len(included_get_params) > 0:
                        get_params["next"] = "%s?%s" % (request.path, urllib.urlencode(included_get_params))
                    else:
                        get_params["next"] = request.path
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
                return redir_view("firststepauth", redirect_with_get_params('login_frontend.authentication_views.firststepauth', get_params))

            if browser.get_auth_state() == Browser.S_REQUEST_STRONG:
                # Login is still valid. Go to second step authentication
                custom_log(request, "Second step authentication requested.", level="debug")
                return redir_view("secondstepauth", redirect_with_get_params("login_frontend.authentication_views.secondstepauth", get_params))


            # Requested authentication level is not satisfied, and user is not proceeding to the second step.
            # Start from the beginning.
            custom_log(request, "Requested authentication level is not satisfied. Start from the first step authentication", level="debug")
            return redir_view("firststepauth", redirect_with_get_params("login_frontend.authentication_views.firststepauth", get_params))

        return inner
    return wrap


@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("firststepauth", required_level=Browser.L_UNAUTH)
def firststepauth(request):
    """ Redirects user to appropriate first factor authentication.
    Currently only username/password query """
    return redirect_with_get_params("login_frontend.authentication_views.authenticate_with_password", request.GET)

@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_password", required_level=Browser.L_UNAUTH)
def authenticate_with_password(request):
    """ Authenticate with username and password """

    ret = {}
    cookies = []
    browser = None

    if request.browser is None:
        # No Browser object is initialized. Create one.
        custom_log(request, "1f: No browser object exists. Create a new one. Cookies: %s" % request.COOKIES, level="debug")
        browser = Browser(bid=create_browser_uuid(), bid_public=create_browser_uuid(), bid_session=create_browser_uuid(), ua=request.META.get("HTTP_USER_AGENT"))
        browser.save()
        cookies.extend(browser.get_cookies())
    else:
        custom_log(request, "1f: Browser object exists", level="debug")
        browser = request.browser
        if browser.get_auth_state() == Browser.S_REQUEST_STRONG:
            # User is already in strong authentication. Redirect them there.
            custom_log(request, "1f: State: REQUEST_STRONG. Redirecting user", level="debug")
            return redirect_with_get_params("login_frontend.authentication_views.secondstepauth", request.GET)
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

        ret["signout_reason"] = bcache.get("%s-signout-reason" % browser.bid_public)

    if request.method == 'POST':
        custom_log(request, "1f: POST request", level="debug")
        username_orig = request.POST.get("username")
        if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
            # Only basic authentication was requested. Take username from session.
            username_orig = browser.user.username
        password = request.POST.get("password")

        if username_orig:
            username_new = map_username(username_orig)
            if username_new != username_orig:
                ret["username_mapped"] = True
                custom_log(request, "1f: mapped username %s to %s" % (username_orig, username_new), level="info")
            username = username_new
        else:
            username = None

        if username and password:
            custom_log(request, "1f: Both username and password exists. username=%s" % username, level="debug")
            auth = LdapLogin(username, password)
            auth_status = auth.login()

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
                bcache.set("activity-%s" % browser.bid_public, True, 86400 * 9)
                bcache.delete("%s-signout-reason" % browser.bid_public)
                browser.password_last_entered_at = timezone.now()
                browser.forced_sign_out = False
                browser_name = dcache.get("browser-name-for-%s-%s" % (browser.bid_public, username))
                if browser_name:
                    # This user named this browser before signing out. Restore that name.
                    browser.name = browser_name

                if browser.user is None:
                    custom_log(request, "1f: browser.user is None: %s" % username, level="debug")
                    (user, _) = User.objects.get_or_create(username=username)
                    user.user_tokens = json.dumps(auth.get_auth_tokens())
                    custom_log(request, "User tokens: %s" % user.user_tokens, level="info")
                    user.save()
                    browser.user = user
                    # Delete cached counter
                    dcache.delete("num_sessions-%s" % username)

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
                    custom_log(request, "1f: Redirecting back to SSO service", level="info")
                    return redir_to_sso(request)

                # TODO: no further authentication is necessarily needed. Determine these automatically.
                if browser.get_auth_state() == Browser.S_REQUEST_BASIC_ONLY:
                    # Only basic authentication is required.
                    custom_log(request, "1f: only basic authentication was required. Upgrade directly to L_STRONG and S_AUTHENTICATED")
                    browser.set_auth_level(Browser.L_STRONG)
                    browser.set_auth_state(Browser.S_AUTHENTICATED)
                    browser.auth_state_changed()
                else:
                    # Continue to strong authentication
                    custom_log(request, "1f: set L_BASIC and S_REQUEST_STRONG")
                    browser.set_auth_level(Browser.L_BASIC)
                    browser.set_auth_state(Browser.S_REQUEST_STRONG)

                return redirect_with_get_params("login_frontend.authentication_views.secondstepauth", request.GET)
            else:
                ret["try_username"] = username
                if auth_status == "invalid_password":
                    ret["invalid_password"] = True
                    if re.match("^[0-9]{5,6}$", password):
                        ret["is_otp"] = True
                    custom_log(request, "1f: Authentication failed. Invalid password", level="warn")
                    add_user_log(request, "Authentication failed. Invalid password", "warning")
                    password_expires = user_cache.get("%s-password_expires" % username)
                    if password_expires and password_expires < timezone.now():
                        ret["password_expired"] = True
                        custom_log(request, "1f: tried to sign in with expired password: %s" % username, level="warning")
                    else:
                        password_changed = user_cache.get("%s-password_changed" % username)
                        ret["password_changed"] = password_changed
                elif auth_status == "invalid_username":
                    ret["invalid_username"] = True
                    custom_log(request, "1f: Authentication failed. Invalid username", level="warn")
                elif auth_status == "server_down":
                    messages.warning(request, "Unable to connect user directory (LDAP). Could not proceed with authentication. Please try again later, and/or contact IT team.")
                    custom_log(request, "1f: LDAP server is down.", level="error")
                else:
                    ret["message"] = auth_status
                    custom_log(request, "1f: Authentication failed: %s" % auth_status, level="warn")
                    add_user_log(request, "Authentication failed: %s" % auth_status, "warning")
        else:
            custom_log(request, "1f: Either username or password is missing.", level="warn")
            msg = "Please enter both username and password."
            if username and not user_cache.get(username):
                msg += " Also, username is invalid."
            elif username:
                ret["try_username"] = username
            messages.warning(request, msg)

    else:
        custom_log(request, "1f: GET request", level="debug")
    if browser:
        ret["my_computer"] = browser.save_browser

    # Keep GET query parameters in form posts.
    ret["get_params"] = urllib.urlencode(request.GET)
    custom_log(request, "1f: Query parameters: %s" % ret["get_params"], level="debug")
    response = render_to_response("login_frontend/authenticate_with_password.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        response.set_cookie(cookie_name, **cookie)
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
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
        return redirect_with_get_params("login_frontend.authentication_views.authenticate_with_sms", get_params)

    if user.strong_sms_always:
        # Strong authentication has been configured, and user has requested to get SMS message.
        custom_log(request, "2f: User has requested SMS authentication.", level="info")
        return redirect_with_get_params("login_frontend.authentication_views.authenticate_with_sms", get_params)

    if user.strong_authenticator_secret:
        custom_log(request, "2f: Authenticator is properly configured. Redirect.", level="info")
        return redirect_with_get_params("login_frontend.authentication_views.authenticate_with_authenticator", get_params)

    custom_log(request, "2f: No proper redirect configured.", level="error")
    return HttpResponse("Second step auth: no proper redirect configured.")

@require_http_methods(["GET", "POST"])
@ratelimit(rate='10/5s', ratekey="2s_url", block=True, method=["POST", "GET"])
@ratelimit(rate='120/1m', ratekey="1m_url", block=True, method=["POST", "GET"])
@ratelimit(rate='1000/6h', ratekey="6h_url", block=True, method=["POST", "GET"])
# This method should not protected with protect_view. In this case, it is important to show specific error messages.
def authenticate_with_url(request, **kwargs):
    """ Authenticates user with URL sent via SMS """
    def sid_cleanup(sid):
        keys = ["urlauth-%s-%s" % (k, sid) for k in ("params", "user", "bid")]
        dcache.delete(keys)

    if is_ratelimited(request, True, True, ["POST"], None, "10/30s", [request.user.username], "30s_url"):
        ret["ratelimited"] = True
        ret["ratelimit_wait_until"] = timezone.now() + datetime.timedelta(seconds=120)
        custom_log(request, "2f-url: ratelimited")
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    template_name = "login_frontend/authenticate_with_url.html"
    sid = kwargs.get("sid")
    ret = {}
    if not hasattr(request, "browser") or not request.browser or not request.browser.user:
        custom_log(request, "2f-url: No browser object / no signed-in user", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    if not dcache.get("urlauth-params-%s" % sid):
        custom_log(request, "2f-url: sid does not exist, or it expired.", level="warn")
        ret["invalid_sid"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    username = dcache.get("urlauth-user-%s" % sid)
    if username != request.browser.user.username:
        custom_log(request, "2f-url: Tried to access SID that belongs to another user.", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    bid_public = dcache.get("urlauth-bid-%s" % sid)
    if bid_public != request.browser.bid_public:
        custom_log(request, "2f-url: Tried to access SID with wrong browser. Probably the phone opens SMS links to different browser, or it was actually another phone.", level="warn")
        ret["wrong_browser"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    get_params = dcache.get("urlauth-params-%s" % sid)
    try:
        get_params_dict = json.loads(get_params)
    except (ValueError, EOFError):
        custom_log(request, "2f-url: Invalid get_params json from cache", level="warn")
        ret["invalid_request"] = True
        return render_to_response(template_name, ret, context_instance=RequestContext(request))

    if request.browser.is_authenticated():
        custom_log(request, "2f-url: User is already signed in. Redirect to secondstepauth: %s" % get_params, level="info")
        sid_cleanup(sid)
        request.browser.revoke_sms()
        return redirect_with_get_params("login_frontend.authentication_views.secondstepauth", get_params_dict)

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
    sid_cleanup(sid)
    request.browser.revoke_sms()
    custom_log(request, "2f-url: Successfully authenticated with URL. Redirecting to secondstepauth", level="info")
    add_user_log(request, "Successfully authenticated with URL.", "lock")
    return redirect_with_get_params("login_frontend.authentication_views.secondstepauth", get_params_dict)


@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
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

    skips_available = user.strong_skips_available
    ret["skips_available"] = skips_available

    if not user.strong_authenticator_secret:
        # Authenticator is not configured. Redirect back to secondstep main screen
        custom_log(request, "2f-auth: Authenticator is not configured, but user accessed Authenticator view. Redirect back to secondstepauth", level="error")
        messages.warning(request, "You tried to authenticate with Authenticator. However, according to our records, you don't have it configured. Please sign in and go to settings to do that.")
        return redirect_with_get_params("login_frontend.authentication_views.secondstepauth", request.GET)

    if not user.strong_authenticator_used:
        custom_log(request, "2f-auth: Authenticator has not been used. Generated at %s" % user.strong_authenticator_generated_at, level="debug")
        ret["authenticator_not_used"] = True
        ret["authenticator_generated"] = user.strong_authenticator_generated_at

    emergency_codes = user.get_emergency_codes()
    if emergency_codes and emergency_codes.valid():
        ret["can_use_emergency"] = True

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

    if request.browser.name:
        ret["browser_name"] = True

    if request.method == "POST" and not request.session.test_cookie_worked():
        custom_log(request, "2f-auth: cookies do not work properly", level="warn")
        ret["enable_cookies"] = True

    elif request.method == "POST":
        browser_name = request.POST.get("name")
        ret["browser_name_value"] = browser_name
        request.session.delete_test_cookie()

        custom_log(request, "2f-auth: POST request", level="debug")
        if is_ratelimited(request, True, False, ["POST"], None, "30/30s", [request.user.username], "30s_2f"):
            ret["ratelimited"] = True
            ret["ratelimit_wait_until"] = timezone.now() + datetime.timedelta(seconds=120)
            custom_log(request, "2f-auth: ratelimited", level="warn")
        elif request.POST.get("otp"):
            custom_log(request, "2f-auth: Form is valid", level="debug")
            otp = request.POST.get("otp")
            otp = otp.replace(" ", "") # spaces doesn't matter
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
                request.browser.twostep_last_entered_at = timezone.now()
                if browser_name and browser_name != request.browser.name:
                    request.browser.name = browser_name

                new_device_notify(request, "authenticator")

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

                if request.browser.name:
                    request.browser.auth_state_changed()
                    custom_log(request, "2f-auth: Redirecting back to SSO provider", level="debug")
                    return redir_to_sso(request)
                else:
                    custom_log(request, "2f-auth: Browser name is not set. Redirect to naming view", level="debug")
                    # Don't send auth_state_changed(), as it would redirect all browser windows to name form
                    get_params = request.GET.dict()
                    get_params["_sc"] = "on"
                    return redirect_with_get_params("login_frontend.views.name_your_browser", get_params)
            else:
                custom_log(request, "2f-auth: Incorrect Authenticator OTP provided: %s" % message, level="warn")
                add_user_log(request, "Incorrect Authenticator OTP provided: %s" % message, "warning")
                if not re.match("^[0-9]{5,6}$", otp):
                    ret["is_invalid_otp"] = True
                ret["invalid_otp"] = message
        else:
            custom_log(request, "2f-auth: form was not valid", level="debug")
            messages.warning(request, "One-time password field is mandatory.")
    else:
        custom_log(request, "2f-auth: GET request", level="debug")

    ret["user"] = user
    ret["authenticator_id"] = user.get_authenticator_id()
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser
    ret["should_timesync"] = request.browser.should_timesync()
    request.session.set_test_cookie()

    response = render_to_response("login_frontend/authenticate_with_authenticator.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
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
            request.browser.auth_state_changed()
            custom_log(request, "2f-sms: Redirecting back to SSO provider", level="debug")
            return redir_to_sso(request)
        else:
            messages.warning(request, "You can't skip strong authentication anymore.")
            custom_log(request, "2f-sms: Tried to skip strong authentication with no skips available", level="warn")

    emergency_codes = user.get_emergency_codes()
    if emergency_codes and emergency_codes.valid():
        ret["can_use_emergency"] = True

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

    if request.browser.name:
        ret["browser_name"] = True

    if request.method == "POST":
        custom_log(request, "2f-sms: POST request", level="debug")
        browser_name = request.POST.get("name")
        ret["browser_name_value"] = browser_name
        if is_ratelimited(request, True, True, ["POST"], None, "60/15m", [request.user.username], "30s_sms"):
            ret["ratelimited"] = True
            ret["ratelimit_wait_until"] = timezone.now() + datetime.timedelta(seconds=900)
            custom_log(request, "2f-sms: ratelimited", level="warn")

        elif request.POST.get("otp"):
            custom_log(request, "2f-sms: Form is valid", level="debug")
            otp = request.POST.get("otp")
            otp = otp.replace(" ", "") # spaces doesn't matter
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
                request.browser.twostep_last_entered_at = timezone.now()
                if browser_name and browser_name != request.browser.name:
                    request.browser.name = browser_name

                new_device_notify(request, "sms")

                # Authentication succeeded.
                custom_log(request, "2f-sms: Second-factor authentication with SMS succeeded")
                add_user_log(request, "Second-factor authentication with SMS succeeded", "lock")
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                if user.primary_phone_changed:
                    user.primary_phone_changed = False
                    user.save()

                if request.POST.get("timing_data"):
                    custom_log(request, "2f-sms: Saved timing data", level="debug")
                    timing_data = request.POST.get("timing_data")
                    save_timing_data(request, user, timing_data)


                if not user.strong_configured:
                    # Strong authentication is not configured. Go to configuration view.
                    custom_log(request, "2f-sms: User has not configured strong authentication. Redirect to configuration view", level="info")
                    return redirect_with_get_params("login_frontend.views.configure", request.GET)
                # Redirect back to SSO service
                if request.browser.name:
                    request.browser.auth_state_changed()
                    custom_log(request, "2f-sms: Redirecting back to SSO provider", level="debug")
                    return redir_to_sso(request)
                else:
                    custom_log(request, "2f-sms: Browser name is not set. Redirect to naming view", level="debug")
                    # Don't send auth_state_changed(), as it would redirect all browser windows to name form
                    get_params = request.GET.dict()
                    get_params["_sc"] = "on"
                    return redirect_with_get_params("login_frontend.views.name_your_browser", get_params)
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

    if not request.browser.valid_sms_exists(180) or request.POST.get("regen_sms"):
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
        if request.method == "POST":
            # Redirect to avoid duplicate SMSes on reload.
            return redirect_with_get_params("login_frontend.authentication_views.authenticate_with_sms", request.GET)

    ret["sms_valid_until"] = request.browser.sms_code_generated_at + datetime.timedelta(seconds=900)
    ret["expected_sms_id"] = request.browser.sms_code_id
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["my_computer"] = request.browser.save_browser
    ret["should_timesync"] = request.browser.should_timesync()

    response = render_to_response("login_frontend/authenticate_with_sms.html", ret, context_instance=RequestContext(request))
    return response

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
        return redirect_with_get_params("login_frontend.authentication_views.logoutview", ret_dict)
    else:
        ret = {}
        if request.GET.get("logout") == "on":
            ret["signed_out"] = True
            active_sessions = request.session.get("active_sessions", [])
            if len(active_sessions) > 0:
                custom_log(request, "logout: active sessions: %s" % active_sessions, level="info")
            ret["active_sessions"] = active_sessions
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

@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="2s", block=True, method=["POST", "GET"])
@ratelimit(rate='300/1m', ratekey="1m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
@protect_view("authenticate_with_emergency", required_level=Browser.L_BASIC)
def authenticate_with_emergency(request):
    """ TODO: emergency code authentication """
    ret = {}
    get_params = request.GET.dict()
    codes = request.browser.user.get_emergency_codes()
    if not codes:
        ret["no_codes_generated"] = True
        custom_log(request, "No codes generated. Can't authenticate with emergency codes.", level="info")
        return render_to_response("login_frontend/no_emergency_available.html", {}, context_instance=RequestContext(request))
    if not codes.valid():
        ret["no_codes_available"] = True
        custom_log(request, "No codes available. Can't authenticate with emergency codes.", level="info")
        return render_to_response("login_frontend/no_emergency_available.html", {}, context_instance=RequestContext(request))

    if request.method == 'POST':
        otp = request.POST.get("otp", "")
        if otp:
            # whitespace is not important, but printed passwords include spaces for readability.
            otp = otp.replace(" ", "")
        if is_ratelimited(request, True, True, ["POST"], None, "30/30s", [request.user.username], "30s_emergency"):
            ret["ratelimited"] = True
            ret["ratelimit_wait_until"] = timezone.now() + datetime.timedelta(seconds=120)
            custom_log(request, "2f-emergency: ratelimited", level="warn")
        elif codes.use_code(otp):
            # Proper code was provided.
            familiar_device = request.browser.user_is_familiar(request.browser.user, Browser.L_STRONG)
            emergency_used_notify(request, codes, familiar_device=familiar_device)
            custom_log(request, "Authenticated with emergency code", level="info")
            add_user_log(request, "Second-factor authentication with emergency code succeeded.", "lock")
            request.browser.save_browser = False # emergency codes are only for temporary authentication
            request.browser.set_auth_level(Browser.L_STRONG)
            request.browser.set_auth_state(Browser.S_AUTHENTICATED)
            return redir_to_sso(request)
        else:
            if re.match("^[0-9]{5,7}$", otp):
                custom_log(request, "Tried to enter SMS/authenticator code", level="info")
                ret["twostep_code"] = True
            if re.match("^[0-9]{8}$", otp):
                custom_log(request, "Tried to use Google apps emergency code", level="info")
                ret["gapps_code"] = True
            custom_log(request, "Incorrect emergency code", level="info")
            ret["invalid_otp"] = True

    ret["generated_at"] = str(codes.generated_at)
    ret["should_timesync"] = request.browser.should_timesync()
    ret["get_params"] = urllib.urlencode(get_params)
    ret["emergency_code_id"] = codes.current_code.code_id
    return render_to_response("login_frontend/authenticate_with_emergency_code.html", ret, context_instance=RequestContext(request))
