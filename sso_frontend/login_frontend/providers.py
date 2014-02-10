from M2Crypto import DSA
from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth.models import User as DjangoUser
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from models import Browser, BrowserLogin
from urlparse import urlparse
from utils import custom_redirect
import Cookie
import auth_pubtkt
import base64
import datetime
import json
import logging
import time
import urllib

#TODO: store private key path in settings.
privkey = settings.PUBTKT_PRIVKEY

log = logging.getLogger(__name__)

def internal_login(request):
    log.debug("Internal login requested")
    params = request.GET.dict()
    params["_sso"] = "internal"
    ret = {}
    browser = request.browser
    if browser is None:
        log.debug("Browser is None. Redirect to first step authentication")
        return custom_redirect("login_frontend.views.firststepauth", params)

    if request.GET.get("next") is None:
        # No back url is defined. Go to front page.
        log.debug("No back URL is defined. Redirect to the front page")
        return HttpResponseRedirect(reverse("login_frontend.views.indexview"))



    # TODO: static auth level
    if browser.get_auth_level() == Browser.L_STRONG:
        log.debug("User is authenticated with strong authentication")
        back_url = request.GET.get("next")
        (user, created) = DjangoUser.objects.get_or_create(username=browser.user.username, defaults={"email": browser.user.email, "is_staff": False, "is_active": True, "is_superuser": False, "last_login": datetime.datetime.now(), "date_joined": datetime.datetime.now()})
        user.backend = 'django.contrib.auth.backends.ModelBackend' # Horrible hack.
        django_login(request, user)

        ret["back_url"] = back_url
        response = render_to_response("html_redirect.html", ret, context_instance=RequestContext(request))
        return response

    return custom_redirect("login_frontend.views.firststepauth", params)

def pubtkt(request):
    def is_valid_back_url(back_url):
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

    log.debug("pubtkt provider initialized. Cookies: %s" % request.COOKIES)

    ret = {}
    cookies = []

    params = request.GET.dict()
    params["_sso"] = "pubtkt"
    ret["get_params"] = urllib.urlencode(params)

    browser = request.browser
    if browser is None:
        return custom_redirect("login_frontend.views.firststepauth", params)

    show_error_page = False

    back_url = request.GET.get("back")

    if "unauth" in request.GET:
        ret["unauth"] = True
        ret["back_url"] = back_url
        show_error_page = True
        log.info("User was not authorized to the service")
    elif back_url is None:
        # No back url is defined. Show error page.
        show_error_page = True
        ret["invalid_back_url"] = True
        log.info("Back URL is not defined")
    elif not is_valid_back_url(back_url):
        show_error_page = True
        ret["invalid_back_url"] = True
        ret["back_url"] = back_url
        log.info("Back URL was invalid")

    if show_error_page:
        return render_to_response("pubtkt_error.html", ret, context_instance=RequestContext(request))

    # TODO: static auth level
    if browser.get_auth_level() == Browser.L_STRONG:
        # TODO: ticket expiration time
        expiration_in_seconds = 3600 * 9
        valid_until = int(time.time() + expiration_in_seconds)
        tokens = json.loads(browser.user.user_tokens)
        ticket = auth_pubtkt.create_ticket(privkey, browser.user.username, valid_until, tokens=tokens)
        cookies.append(("auth_pubtkt", {"value": urllib.quote(ticket), "secure": True, "httponly": True, "domain": ".futurice.com"}))
        ret["back_url"] = back_url
        response = render_to_response("html_redirect.html", ret, context_instance=RequestContext(request))

        # Add/update BrowserLogin
        d_valid_until = timezone.now() + datetime.timedelta(seconds=expiration_in_seconds)
        (browser_login, _) = BrowserLogin.objects.get_or_create(user=browser.user, browser=browser, sso_provider="pubtkt", defaults={"auth_timestamp": timezone.now(), "expires_at": d_valid_until})
        browser_login.auth_timestamp = timezone.now()
        browser_login.expires_at = d_valid_until
        browser_login.save()

        # Set cookies
        for cookie_name, cookie in cookies:
            log.debug("Setting cookie: %s=%s" % (cookie_name, cookie))
            response.set_cookie(cookie_name, **cookie) 
        log.debug("Redirecting to %s with html redirect" % back_url)
        return response

    return custom_redirect("login_frontend.views.firststepauth", params)
