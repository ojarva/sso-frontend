from django.shortcuts import render

from StringIO import StringIO
from io import BytesIO
from django.conf import settings
from django.contrib import messages
from django.core.cache import get_cache
from django.core.mail import mail_admins
from django.core.urlresolvers import reverse
from django.core.validators import validate_email
from django.db.models import Q
from django.http import HttpResponseForbidden, HttpResponse, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods
from django_statsd.clients import statsd as sd
from login_frontend.authentication_views import protect_view
from login_frontend.models import *
from login_frontend.providers import pubtkt_logout
from login_frontend.emails import new_authenticator_notify, new_emergency_generated_notify
from login_frontend.utils import get_geoip_string, redirect_with_get_params, redir_to_sso, paginate, check_browser_name, store_location_caching, get_return_url, get_ratelimit_keys
from ratelimit.decorators import ratelimit
import datetime
import json
import logging
import math
import os
import simplekml
import pyotp
import qrcode
import re
import redis
import sys
import textwrap
import time
import urllib
import urlparse
import p0f


dcache = get_cache("default")

log = logging.getLogger(__name__)

@sd.timer("datacollection.views.custom_log")
def custom_log(request, message, **kwargs):
    """ Automatically logs username, remote IP and bid_public """
    level = kwargs.get("level", "info")
    method = getattr(log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    data_id = request.COOKIES.get("data_id", "")
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("%s - %s - %s - %s - %s",
        remote_addr, username, bid_public, data_id, message)

@require_http_methods(["POST"])
def location(request):
    location = request.POST.dict()
    if all (k in location for k in ("longitude", "latitude", "accuracy")):
        data = {}
        for k in ("longitude", "latitude", "altitude", "accuracy", "altitude_accuracy", "heading", "speed"):
            try:
                data[k] = float(location.get(k))
            except ValueError:
                data[k] = None
        if hasattr(request, "browser") and request.browser:
            data["bid_public"] = request.browser.bid_public
            if request.browser.user:
                data["user"] = request.browser.user.username
        data["data_id"] = request.COOKIES.get("data_id", "")
        data["remote_ip"] = request.META.get("REMOTE_ADDR")

        custom_log(request, "Recorded a new location: %s" % data, level="info")
        response = HttpResponse("OK")
        response.set_cookie("ask_location", value="1", secure=settings.SECURE_COOKIES)
    else:
        custom_log(request, "Missing mandatory fields: %s" % location)
        response = HttpResponse("Missing mandatory fields")
    return response

@require_http_methods(["POST"])
def browser_details(request):
    custom_log(request, "Browser details: %s" % request.POST.dict())
    return HttpResponse("OK")

@require_http_methods(["GET", "POST"])
def index(request):
    ret = {}
    data_id = request.COOKIES.get("data_id")
    if not data_id:
        data_id = create_browser_uuid()
        bid_public = None
        if hasattr(request, "browser") and request.browser:
            bid_public = request.browser.bid_public
        custom_log(request, "Creating new data_id: %s. bid_public=%s. UA=%s" % (data_id, bid_public, request.META.get("HTTP_USER_AGENT")), level="info")

    if request.method == "POST":
        if request.POST.get("background_form"):
            custom_log(request, "Background form: %s" % request.POST.dict())
            return HttpResponse("OK")
        if request.POST.get("password"):
            custom_log(request, "Keystroke timing: %s" % request.POST.dict())
            return HttpResponse("OK")
    try:
        p0fapi = p0f.P0f(settings.P0F_SOCKET)
        p0finfo = p0fapi.get_info(request.META.get("REMOTE_ADDR"))
        ret["uptime"] = p0finfo.get("uptime")
        custom_log(request, "p0f: %s" % p0finfo)
    except:
        custom_log(request, "p0f failed")

    ret["data_id"] = data_id
    response = render_to_response("datacollection/index.html", ret, context_instance=RequestContext(request))
    response.set_cookie("data_id", **{"value": data_id, "secure": settings.SECURE_COOKIES, "httponly": False})
    return response
