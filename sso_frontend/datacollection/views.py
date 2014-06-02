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
from login_frontend.utils import get_geoip_string, redirect_with_get_params, redir_to_sso, paginate, check_browser_name, store_location_caching, get_return_url, get_ratelimit_keys, is_private_net
from ratelimit.decorators import ratelimit
import datetime
import json
import logging
import countries
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
import math
from maxmind import get_omni_data
from login_frontend.utils import geo

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


def distance_on_unit_sphere(lat1, long1, lat2, long2):
    # Code from http://www.johndcook.com/python_longitude_latitude.html
    # Released under public domain.

    # Convert latitude and longitude to
    # spherical coordinates in radians.
    degrees_to_radians = math.pi/180.0

    # phi = 90 - latitude
    phi1 = (90.0 - lat1)*degrees_to_radians
    phi2 = (90.0 - lat2)*degrees_to_radians

    # theta = longitude
    theta1 = long1*degrees_to_radians
    theta2 = long2*degrees_to_radians

    # Compute spherical distance from spherical coordinates.

    # For two locations in spherical coordinates
    # (1, theta, phi) and (1, theta, phi)
    # cosine( arc length ) =
    #    sin phi sin phi' cos(theta-theta') + cos phi cos phi'
    # distance = rho * arc length

    cos = (math.sin(phi1)*math.sin(phi2)*math.cos(theta1 - theta2) +
           math.cos(phi1)*math.cos(phi2))
    arc = math.acos( cos )

    # Remember to multiply arc by the radius of the earth
    # in your favorite set of units to get length.
    return arc * 6373

def get_omni_response(request, ip, coords):
    def get_confidence_class(confidence):
        try:
            confidence = float(confidence)
        except:
            return "unknown"
        if confidence > 90:
            return "very high"
        if confidence > 75:
            return "high"
        if confidence > 50:
            return "reasonable"
        if confidence > 25:
            return "low"
        return "dimishing"
    ret = {}
    private_net = is_private_net(ip)
    if private_net:
        return HttpResponse("You're connected from %s." % private_net)
    try:
        omni = get_omni_data(ip)
        if "error" in omni:
            print omni
            return None
    except ValueError, e:
        custom_log(request, "omni returned exception: %s" % e, level="error")
        print e
        return None
    response_location = []
    fields = (("Continent", "continent"), ("Country", "country"), ("City", "city"))
    for desc, field in fields:
        if field in omni:
            c = omni[field]
            if not "names" in c:
                continue
            response_location.append({"k": desc, "v": "%s (%s confidence)" % (c["names"]["en"], get_confidence_class(c.get("confidence", None)))})
    ret["fields"] = response_location
    if "location" in omni:
        c = omni["location"]
        if "latitude" in c and "longitude" in c:
            ret["latitude"] = c["latitude"]
            ret["longitude"] = c["longitude"]
            distance_km = distance_on_unit_sphere(c["latitude"], c["longitude"], coords["latitude"], coords["longitude"])
            ret["distance"] = round(distance_km)
            if "accuracy_radius" in c:
                ret["accuracy_radius"] = float(c["accuracy_radius"]) / 2 # coarse approximation
    return render_to_response("datacollection/snippets/geoip.html", ret)

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
        response = get_omni_response(request, request.META.get("REMOTE_ADDR"), data)
        if not response:
            response = HttpResponse("No geoIP data is available for your IP address")
        response.set_cookie("ask_location", value="1", secure=settings.SECURE_COOKIES)
    else:
        custom_log(request, "Missing mandatory fields: %s" % location)
        response = HttpResponse("Missing mandatory fields")
    return response

@require_http_methods(["POST"])
def location_only(request):
    location = request.POST.dict()
    data_id = request.COOKIES.get("data_id")
    if not data_id:
        return HttpResponse("You must enable cookies before visiting this site")
    if (all (k in location for k in ("longitude", "latitude", "accuracy"))):
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
        data["data_id"] = data_id
        data["remote_ip"] = request.META.get("REMOTE_ADDR")
        custom_log(request, "Recorded a new location_only: %s" % data, level="info")
        data_id_resp = "%s%s" % (datetime.date.today().day, data_id)
        try:
            if float(data["accuracy"]) > 25000:
                return HttpResponse("Sorry! Your browser doesn't provide accurate enough information. You can't complete this task with your device.")
        except:
            pass
        response = HttpResponse("OK: this is your proof for finishing the task: <strong>%s</strong>" % data_id_resp)
        try:
            cc = countries.CountryChecker(settings.PROJECT_ROOT+'data/TM_WORLD_BORDERS-0.3.shp')
            d = cc.getCountry(countries.Point(data["latitude"], data["longitude"]))
            if d.iso in ("NP", "IN", "BD", "PK", "MA"):
                custom_log(request, "User location is %s, which is banned." % d.iso)
                response = HttpResponse("Fail: you may not use proxy for this task. Your country is %s, which does not match to what you reported." % d)
        except:
            pass
        response.set_cookie("ask_location", value="1", secure=settings.SECURE_COOKIES)
    else:
        custom_log(request, "Missing mandatory fields: %s" % location)
        response = HttpResponse("Invalid location data - your browser does not support this")
    return response

@require_http_methods(["POST"])
def browser_details(request):
    custom_log(request, "Browser details: %s" % request.POST.dict())
    return HttpResponse("OK")

@require_http_methods(["GET", "POST"])
def index_location_only(request):
    data_id = request.COOKIES.get("data_id")
    ret = {}
    if not data_id:
        data_id = create_browser_uuid()
        bid_public = None
        if hasattr(request, "browser") and request.browser:
            bid_public = request.browser.bid_public
        custom_log(request, "Creating new data_id for location only: %s. bid_public=%s. UA=%s" % (data_id, bid_public, request.META.get("HTTP_USER_AGENT")), level="info")

    try:
        p0fapi = p0f.P0f(settings.P0F_SOCKET)
        p0finfo = p0fapi.get_info(request.META.get("REMOTE_ADDR"))
        ret["uptime"] = p0finfo.get("uptime")
        custom_log(request, "p0f: %s" % p0finfo)
    except:
        custom_log(request, "p0f failed")
    ret["data_id"] = data_id

    if request.POST.get("connection_type"):
        custom_log(request, "Connection type: %s" % request.POST.dict())
        return HttpResponse("OK")

    if dcache.get("location-only-%s" % request.META.get("REMOTE_ADDR")):
        custom_log(request, "IP %s has already participated. Show error message." % (request.META.get("REMOTE_ADDR")))
        ret["already_participated"] = True
    try:
     d = geo.city(request.META.get("REMOTE_ADDR"))
     if d.country.iso_code in ("NP", "IN", "BD", "PK", "MA"):
        ret["already_participated"] = True
    except:
     pass

    response = render_to_response("datacollection/index_location_only.html", ret, context_instance=RequestContext(request))
    response.set_cookie("data_id", value=data_id, secure=settings.SECURE_COOKIES, max_age=86400*180)
    return response



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
        if request.POST.get("connection_type"):
            custom_log(request, "Connection type: %s" % request.POST.dict())
            return HttpResponse("OK")

    try:
        p0fapi = p0f.P0f(settings.P0F_SOCKET)
        p0finfo = p0fapi.get_info(request.META.get("REMOTE_ADDR"))
        ret["uptime"] = p0finfo.get("uptime")
        custom_log(request, "p0f: %s" % p0finfo)
    except:
        custom_log(request, "p0f failed")
    ret["data_id"] = data_id

    if hasattr(request, "browser") and request.browser and request.browser.user:
        if request.browser.user.location_authorized:
            custom_log(request, "Location automatically enabled, as user has opted in in settings", level="debug")
            ret["location_auto_enabled"] = True
    response = render_to_response("datacollection/index.html", ret, context_instance=RequestContext(request))
    if "location_auto_enabled" in ret:
        response.set_cookie("ask_location", value="1", secure=settings.SECURE_COOKIES, max_age=86400*180)
    response.set_cookie("data_id", value=data_id, secure=settings.SECURE_COOKIES, max_age=86400*180)
    return response
