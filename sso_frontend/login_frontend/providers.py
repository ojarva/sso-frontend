from M2Crypto import DSA
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from models import Browser
from utils import custom_redirect, get_browser
import Cookie
import auth_pubtkt
import base64
import json
import time
import urllib
import datetime
from django.contrib.auth.models import User as DjangoUser
from django.contrib.auth import login as django_login

#TODO: store private key path in settings.
privkey = DSA.load_key("/var/www/private/privkey1.pem")


def internal_login(request):
    params = request.GET.dict()
    params["_sso"] = "internal"
    ret = {}
    cookies = []
    browser = get_browser(request)
    if browser is None:
        return custom_redirect("login_frontend.views.firststepauth", params)

    if request.GET.get("next") is None:
        # No back url is defined. Go to front page.
        return HttpResponseRedirect(reverse("login_frontend.views.indexview"))

    # TODO: static auth level
    if browser.get_auth_level() == Browser.L_STRONG:
        back_url = request.GET.get("next")
        (user, created) = DjangoUser.objects.get_or_create(username=browser.username.username, defaults={"email": browser.username.email, "is_staff": False, "is_active": True, "is_superuser": False, "last_login": datetime.datetime.now(), "date_joined": datetime.datetime.now()})
        user.backend = 'django.contrib.auth.backends.ModelBackend' # Horrible hack.
        django_login(request, user)

        ret["back_url"] = back_url
        response = render_to_response("html_redirect.html", ret, context_instance=RequestContext(request))
        for cookie_name, cookie in cookies:
            response.set_cookie(cookie_name, **cookie) 
        return response

    return custom_redirect("login_frontend.views.firststepauth", params)

def saml(request):
    pass

def pubtkt(request):
    ret = {}
    cookies = []

    params = request.GET.dict()
    params["_sso"] = "pubtkt"
    browser = get_browser(request)
    if browser is None:
        return custom_redirect("login_frontend.views.firststepauth", params)

    if request.GET.get("back") is None:
        # No back url is defined. Go to front page.
        return HttpResponseRedirect(reverse("login_frontend.views.indexview"))

    # TODO: static auth level
    if browser.get_auth_level() == Browser.L_STRONG:
        # TODO: ticket expiration time
        valid_until = int(time.time() + 3600 * 9)
        tokens = json.loads(browser.username.user_tokens)
        ticket = auth_pubtkt.create_ticket(privkey, browser.username.username, valid_until, tokens=tokens)
        cookies.append(("auth_pubtkt", {"value": urllib.quote(ticket), "secure": True, "httponly": True, "domain": ".futurice.com"}))
        back_url = request.GET.get("back")
        ret["back_url"] = back_url
        response = render_to_response("html_redirect.html", ret, context_instance=RequestContext(request))
        for cookie_name, cookie in cookies:
            response.set_cookie(cookie_name, **cookie) 
        return response

    return custom_redirect("login_frontend.views.firststepauth", params)
