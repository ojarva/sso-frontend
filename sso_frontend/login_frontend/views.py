from StringIO import StringIO
from django.contrib import auth as django_auth
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.timesince import timeuntil
from django.views.decorators.http import require_http_methods
from dummy import *
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

r = redis.Redis()


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
    cookies = []
    ret["username"] = request.browser.user.username

    response = render_to_response("indexview.html", ret, context_instance=RequestContext(request))
    for cookie_name, cookie in cookies:
        response.set_cookie(cookie_name, **cookie)

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
        browser = Browser(bid=create_browser_uuid(), ua=request.META.get("HTTP_USER_AGENT"))
        browser.save()
        cookies.append(browser.get_cookie())
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
                    return custom_redirect("login_frontend.views.secondstepauth", request.GET)
            else:
                if auth_status == "invalid_credentials":
                    ret["authentication_failed"] = True
                else:
                    ret["message"] = auth_status 
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
                user.strong_authenticator_used = True
                user.save()
                # TODO: determine the levels automatically.
                request.browser.set_auth_level(Browser.L_STRONG)
                request.browser.set_auth_state(Browser.S_AUTHENTICATED)
                request.browser.save()
                return redir_to_sso(request)
            else:
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
                if not user.strong_configured:
                    # Strong authentication is not configured. Go to configuration view.
                    return custom_redirect("login_frontend.views.configure_strong", request.GET)
                # Redirect back to SSO service
                return redir_to_sso(request)
            else:
                if message:
                    ret["message"] = message
                else:
                    ret["authentication_failed"] = True
    else:
        form = OTPForm()

    if request.method == "GET" or request.GET.get("regen_sms") or not request.browser.valid_sms_exists():
        sms_text = request.browser.generate_sms_text()
        for phone in (user.primary_phone, user.secondary_phone):
            if phone:
                status = send_sms(phone, sms_text)
                if not status:
                    ret["message"] = "Sending sms to %s failed." % phone

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

    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("configure_strong.html", ret, context_instance=RequestContext(request))
    return response


@protect_view("get_authenticator_qr", required_level=Browser.L_STRONG)
def get_authenticator_qr(request, **kwargs):
    """ Outputs QR code for Authenticator. Uses single_use_code to prevent
    reloading / linking. """
    if not request.browser.authenticator_qr_nonce == kwargs["single_use_code"]:
        # TODO: render image
        return HttpResponse("Invalid one-time code: unable to show QR")

    # Delete QR nonce to prevent replay.
    request.browser.authenticator_qr_nonce = None
    request.browser.save()

    totp = pyotp.TOTP(request.browser.user.strong_authenticator_secret)
    img = qrcode.make(totp.provisioning_uri(request.browser.user.username+"@futu"))
    stringio = StringIO()
    img.save(stringio)
    stringio.seek(0)
    return HttpResponse(stringio.read(), content_type="image/png")

@protect_view("configure_authenticator", required_level=Browser.L_STRONG)
def configure_authenticator(request):
    """ Google Authenticator configuration view. Only POST requests are allowed. """
    ret = {}
    user = request.browser.user
    if request.method != "POST":
        return custom_redirect("login_frontend.views.configure_strong", request.GET)

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
            return redir_to_sso(request)
        else:
            # Incorrect code. Don't regen secret.
            regen_secret = False
            ret["invalid_otp"] = message

    if regen_secret:
        authenticator_secret = user.gen_authenticator()
        ret["authenticator_secret"] = authenticator_secret
        user.strong_authenticator_used = False
        user.save()

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
