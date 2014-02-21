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
from models import Browser
import logging
import redis

log = logging.getLogger(__name__)
r = redis.Redis()


@require_http_methods(["GET", "POST"])
def error_csrf(request, reason="", **kwargs):
    ret = {}
    if len(request.COOKIES) == 0:
        ret["no_cookies"] = True
    response = render_to_response("login_frontend/errors/csrf_fail.html", ret, context_instance=RequestContext(request))
    response.status_code = "403"
    response.reason_phrase = "Forbidden"
    return response

@require_http_methods(["GET", "POST"])
def error_400(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/400.html", ret, context_instance=RequestContext(request))

    # Upon bad request, delete all session data.
    if request.browser:
        request.browser.delete()

    response.delete_cookie(Browser.C_BID)
    response.delete_cookie(Browser.C_BID_PUBLIC)
    response.delete_cookie(Browser.C_BID_SESSION)
    response.delete_cookie("auth_pubtkt")
    response.delete_cookie("csrftoken")
    response.delete_cookie("sessionid")
    response.delete_cookie("slogin")
    response.status_code = "400"
    response.reason_phrase = "Bad Request"
    return response


@require_http_methods(["GET", "POST"])
def error_403(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/403.html", ret, context_instance=RequestContext(request))
    response.status_code = "403"
    response.reason_phrase = "Forbidden"
    return response


@require_http_methods(["GET", "POST"])
def error_404(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/404.html", ret, context_instance=RequestContext(request))
    response.status_code = "404"
    response.reason_phrase = "Not Found"
    return response


@require_http_methods(["GET", "POST"])
def error_500(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/500.html", ret, context_instance=RequestContext(request))
    response.status_code = "500"
    response.reason_phrase = "Internal Server Error"
    return response

