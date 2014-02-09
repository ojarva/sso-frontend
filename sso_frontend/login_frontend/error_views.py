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
import logging
import redis

log = logging.getLogger(__name__)
r = redis.Redis()

@require_http_methods(["GET", "POST"])
def error_400(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get("v2public-browserid")
    response = render_to_response("errors/400.html", ret, context_instance=RequestContext(request))

    # Upon bad request, delete all session data.
    if request.browser:
        request.browser.delete()

    response.delete_cookie("v2public-browserid")
    response.delete_cookie("auth_pubtkt")
    response.delete_cookie("csrftoken")
    response.delete_cookie("v2sessionbid")
    response.delete_cookie("sessionid")
    response.delete_cookie("slogin")
    return response


@require_http_methods(["GET", "POST"])
def error_403(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get("v2public-browserid")
    response = render_to_response("errors/403.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET", "POST"])
def error_404(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get("v2public-browserid")
    response = render_to_response("errors/404.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET", "POST"])
def error_500(request, **kwargs):
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get("v2public-browserid")
    response = render_to_response("errors/500.html", ret, context_instance=RequestContext(request))
    return response

