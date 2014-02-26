#pylint: disable-msg=C0301

"""
SSO providers
"""

from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth.models import User as DjangoUser
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from login_frontend.models import Browser, BrowserLogin, add_user_log
from urlparse import urlparse
from login_frontend.utils import redirect_with_get_params
import auth_pubtkt
import datetime
import json
import logging
import time
import urllib
import os
import sys

privkey = settings.PUBTKT_PRIVKEY

log = logging.getLogger(__name__)

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


__all__ = ["internal_login", "pubtkt_logout", "pubtkt"]

def internal_login(request):
    """ Internal login using Django authentication framework """
    custom_log(request, "Internal login requested. back_url=%s" % request.GET.get("next"), level="debug")
    params = request.GET.dict()
    params["_sso"] = "internal"
    ret = {}
    browser = request.browser
    if browser is None:
        custom_log(request, "Browser is not set. Redirect to first step authentication")
        return redirect_with_get_params("login_frontend.views.firststepauth", params)

    if request.GET.get("next") is None:
        # No back url is defined. Go to front page.
        custom_log(request, "No back URL is defined. Redirect to the front page", level="debug")
        return HttpResponseRedirect(reverse("login_frontend.views.indexview"))



    # TODO: static auth level
    if browser.get_auth_level() >= Browser.L_STRONG:
        back_url = request.GET.get("next")
        custom_log(request, "User is authenticated with strong authentication. Redirecting back to %s" % back_url, level="info")
        (user, _) = DjangoUser.objects.get_or_create(username=browser.user.username, defaults={"email": browser.user.email, "is_staff": False, "is_active": True, "is_superuser": False, "last_login": datetime.datetime.now(), "date_joined": datetime.datetime.now()})
        user.backend = 'django.contrib.auth.backends.ModelBackend' # Horrible hack.
        django_login(request, user)

        ret["back_url"] = back_url
        response = render_to_response("login_frontend/html_redirect.html", ret, context_instance=RequestContext(request))
        return response

    custom_log(request, "More authentication is required. Redirect to first step authentication", level="debug")
    return redirect_with_get_params("login_frontend.views.firststepauth", params)


def pubtkt_logout(request, response = None):
    """ Sets pubtkt logout cookie. """
    if response:
        custom_log(request, "pubtkt_logout: Unsetting pubtkt cookie", level="debug")
        response.set_cookie("auth_pubtkt", **{"value": "invalid", "secure": True, "httponly": True, "domain": ".futurice.com"})
    try:
        if request.browser is None:
            custom_log(request, "pubtkt_logout: No browser set. No further actions. IP: %s" % request.META.get("REMOTE_ADDR"), level="debug")
            return response
    except AttributeError:
        custom_log(request, "pubtkt_logout: No browser set. No further actions. IP: %s" % request.META.get("REMOTE_ADDR"), level="debug")
        return response

    if request.COOKIES.get("auth_pubtkt") and not response:
        # If cookie exists but it was not removed, don't mark as signed out.
        custom_log(request, "pubtkt_logout: cookie exists, but response object was not specified.", level="debug")
        return response

    browser_login = BrowserLogin.objects.filter(browser=request.browser, sso_provider="pubtkt", signed_out=False)
    for login in browser_login:
        custom_log(request, "pubtkt_logout: Marking %s as signed out" % login.id, level="info")
        login.signed_out = True
        login.save()
    return response

def pubtkt(request):
    """ pubtkt login """
    def is_valid_back_url(back_url):
        """ Returns true if back_url should be okay """
        valid_domains = settings.PUBTKT_ALLOWED_DOMAINS
        parsed_url = urlparse(back_url)
        if parsed_url.scheme != "https":
            return False

        if parsed_url.hostname:
            for domain in valid_domains:
                if parsed_url.hostname.endswith(domain):
                    break
            else:
                return False
        else:
            return False
        return True

    custom_log(request, "pubtkt provider initialized. Cookies: %s" % request.COOKIES)

    ret = {}
    cookies = []

    params = request.GET.dict()
    params["_sso"] = "pubtkt"
    ret["get_params"] = urllib.urlencode(params)

    browser = request.browser
    if browser is None:
        custom_log(request, "pubtkt: Browser is not set. Redirect to first step authentication")
        return redirect_with_get_params("login_frontend.views.firststepauth", params)

    show_error_page = False

    back_url = request.GET.get("back")
    custom_log(request, "Requested back_url=%s" % back_url, level="info")
    if "unauth" in request.GET:
        ret["unauth"] = True
        ret["back_url"] = back_url
        show_error_page = True
        custom_log(request, "pubtkt: User is not authorized to access %s" % back_url, level="info")
    elif back_url is None:
        # No back url is defined. Show error page.
        show_error_page = True
        ret["invalid_back_url"] = True
        custom_log(request, "pubtkt: back url is not defined", level="info")
    elif not is_valid_back_url(back_url):
        show_error_page = True
        ret["invalid_back_url"] = True
        ret["back_url"] = back_url
        custom_log(request, "pubtkt: back url is invalid", level="info")

    if show_error_page:
        return render_to_response("login_frontend/pubtkt_error.html", ret, context_instance=RequestContext(request))

    # TODO: static auth level
    if browser.get_auth_level() >= Browser.L_STRONG:
        # TODO: ticket expiration time
        expiration_in_seconds = 3600 * 9
        valid_until = int(time.time() + expiration_in_seconds)
        tokens = json.loads(browser.user.user_tokens)
        ticket = auth_pubtkt.create_ticket(privkey, browser.user.username, valid_until, tokens=tokens)
        cookies.append(("auth_pubtkt", {"value": urllib.quote(ticket), "secure": True, "httponly": True, "domain": ".futurice.com"}))
        ret["back_url"] = back_url
        response = render_to_response("login_frontend/html_redirect.html", ret, context_instance=RequestContext(request))

        # Add/update BrowserLogin
        d_valid_until = timezone.now() + datetime.timedelta(seconds=expiration_in_seconds)
        (browser_login, _) = BrowserLogin.objects.get_or_create(user=browser.user, browser=browser, sso_provider="pubtkt", signed_out=False, defaults={"auth_timestamp": timezone.now(), "expires_at": d_valid_until, "remote_service": back_url})
        browser_login.auth_timestamp = timezone.now()
        browser_login.expires_at = d_valid_until
        browser_login.save()

        add_user_log(request, "Granted pubtkt access (%s)" % back_url, "share-square-o")

        # Set cookies
        for cookie_name, cookie in cookies:
            custom_log(request, "pubtkt: Setting cookie: %s=%s" % (cookie_name, cookie), level="debug")
            response.set_cookie(cookie_name, **cookie) 
        custom_log(request, "pubtkt: redirecting back to %s with html redirect", level="info")
        return response

    custom_log(request, "pubtkt: additional authentication is required. Redirect to first step authentication")
    return redirect_with_get_params("login_frontend.views.firststepauth", params)
