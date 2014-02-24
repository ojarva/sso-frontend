"""
Utility functions
"""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User as DjangoUser
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone
from login_frontend.models import User, BrowserDetails, KeystrokeSequence
import datetime
import dateutil.parser
import geoip2
import geoip2.database
import geoip2.errors
import geoip2.models
import ipaddr
import logging
import json
import login_frontend._slumber_auth as _slumber_auth
import slumber
import time
import urllib
        


log = logging.getLogger(__name__)
timing_log = logging.getLogger("timing_data")

geo = geoip2.database.Reader(settings.GEOIP_DB)
IP_NETWORKS = settings.IP_NETWORKS

__all__ = ["redir_to_sso", "is_private_net", "save_timing_data", "get_and_refresh_user", "refresh_user", "get_geoip_string", "redirect_with_get_params", "dedup_messages"]

def dedup_messages(request, level, message):
    storage = messages.get_messages(request)
    for amessage in storage:
        if unicode(amessage) == unicode(message):
            storage.used = False
            return False
    storage.used = False
    messages.add_message(request, level, message)


def redir_to_sso(request, **kwargs):
    """ Returns HttpResponseRedirect to proper login service. """
    sso = request.GET.get("_sso")
    if sso == "pubtkt":
        log.debug("Redirecting with pubtkt")
        return redirect_with_get_params("login_frontend.providers.pubtkt", request.GET.dict())
    elif sso == "internal":
        log.debug("Redirecting with internal sso")
        return redirect_with_get_params("login_frontend.providers.internal_login", request.GET.dict())
    else:
        log.debug("No sso preference configured")
        if not kwargs.get("no_default", False):
            log.debug("Redirecting back to indexview")
            return redirect_with_get_params("login_frontend.views.indexview", request.GET.dict())
        log.debug("No default configured - return None")
        return None



def is_private_net(ip_address):
    """ Returns True if specified in private networks, imported from
        local_settings """
    try:
        ip = ipaddr.IPv4Address(ip_address)
    except:
        return False

    for (network, _, _, description) in IP_NETWORKS:
        if ((isinstance(network, ipaddr.IPv4Address) and
            ip is network) or
           (isinstance(network, ipaddr.IPv4Network) and
            ip in network)):
            return description
    return False

def save_timing_data(request, user, timing_data):
    """ Saves timing data with username, UA and bid. """
    if not (hasattr(request, "browser") and request.browser):
        log.error("Missing request.browser on timing data input")
        return
    browser = request.browser
    user_agent = request.META.get("HTTP_USER_AGENT")
    bid_public = request.browser.bid_public
    username = user.username
    timing_log.info("%s - %s - %s - %s - %s" % (time.time(), username, user_agent, timing_data, bid_public))

    try:
        data = json.loads(timing_data)
    except (ValueError, EOFError):
        log.error("Unable to load timing data json")
        return

    if not isinstance(data, dict):
        log.error("Invalid timing data dictionary")

    resolution = data.get("resolution")
    remote_clock = data.get("browserclock")
    remote_clock_offset = remote_clock.get("timezoneoffset")
    remote_clock_time = remote_clock.get("utciso")

    plugins = data.get("plugins")

    performance = data.get("performance")
    performance_performance = performance_memory = performance_timing = performance_navigation = None
    if isinstance(performance, dict):
        performance_performance = performance.get("performance")
        performance_memory = performance.get("memory")
        performance_timing = performance.get("timing")
        performance_navigation = performance.get("navigation")

    BrowserDetails.objects.create(browser=browser, timestamp=timezone.now(), remote_clock_offset=str(remote_clock_offset), remote_clock_time=str(remote_clock_time), performance_performance=str(performance_performance), performance_memory=str(performance_memory), performance_timing=str(performance_timing), performance_navigation=str(performance_navigation), resolution=str(resolution), plugins=str(plugins))

    if "id_username" in data:
        fieldname = KeystrokeSequence.USERNAME
        timing = str(data.get("id_username"))
        KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timezone.now(), resolution=resolution, was_correct=True)
    
    if "id_password" in data:
        fieldname = KeystrokeSequence.PASSWORD
        timing = str(data.get("id_password"))
        KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timezone.now(), resolution=resolution, was_correct=True)
 
    if "id_otp" in data:
        if request.path.startswith("/second/sms"):
            fieldname = KeystrokeSequence.OTP_SMS
        else:
            fieldname = KeystrokeSequence.OTP_AUTHENTICATOR
        timing = str(data.get("id_otp"))
        KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timezone.now(), resolution=resolution, was_correct=True)



def get_and_refresh_user(username):
    """ Loads and refreshes user information from LDAP """
    log.info("Refreshing %s" % username)
    api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))
    refresh_user(api.users().get(username=username))

def refresh_user(user):
    """ Refreshes user details, if necessary. """
    username = user.get("username")
    log.info("Updating %s" % username)
    first_name = user.get("first_name", "Unknown")
    last_name = user.get("last_name", "Unknown")
    email = user.get("email", "")
    phone1 = user.get("phone1")
    phone2 = user.get("phone2")
    if username is None or email is None:
        log.debug("%s - %s - Username or email is none - skip" % (username, email))
        return

    if first_name is None:
        first_name = "Unknown"
    if last_name is None:
        last_name = "Unknown"

    (user, created1) = DjangoUser.objects.get_or_create(username=username, 
            defaults={"email": email, "is_staff": False, "is_active": True, "is_superuser": False, "last_login": timezone.now(), "date_joined": timezone.now()})
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.save()

    (obj, created2) = User.objects.get_or_create(username=username)
    changed = obj.refresh_strong(email, phone1, phone2, created=created2)
    if changed or created1 or created2:
        log.info("Changed or created new objects")
        return True

def get_geoip_string(ip_address):
    """ Returns short location string for IP address. """
    private_net = is_private_net(ip_address)
    if private_net:
        return private_net
    try:
        data = geo.city(ip_address)
    except:
        return "Unknown"
    country = data.country.iso_code
    city = data.city.name
    if city is None:
        return "%s" % country
    return "%s (%s)" % (country, city)

def redirect_with_get_params(url_name, get_params = None):
    """ Returns HttpResponseRedirect with query string. """
    url = reverse(url_name)
    if not get_params:
        return HttpResponseRedirect(url)
    params = urllib.urlencode(get_params)
    full_url = url + "?%s" % params
    log.debug("Redirecting to %s" % full_url)
    return HttpResponseRedirect(full_url)

