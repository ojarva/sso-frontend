"""
Utility functions
"""
from django.conf import settings
from django.contrib.auth.models import User as DjangoUser
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.utils import timezone
from login_frontend.models import User
import login_frontend._slumber_auth as _slumber_auth
import geoip2
import time
import geoip2.database
import geoip2.errors
import geoip2.models
import ipaddr
import slumber
import urllib
import logging

log = logging.getLogger(__name__)
timing_log = logging.getLogger("timing_data")

geo = geoip2.database.Reader(settings.GEOIP_DB)
IP_NETWORKS = settings.IP_NETWORKS

__all__ = ["is_private_net", "save_timing_data", "get_and_refresh_user", "refresh_user", "get_geoip_string", "custom_redirect"]

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

def save_timing_data(username, user_agent, timing_data, bid_public):
    """ Saves timing data with username, UA and bid. """
    timing_log.info("%s - %s - %s - %s - %s" % (time.time(), username, user_agent, timing_data, bid_public))


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

def custom_redirect(url_name, get_params = None):
    """ Returns HttpResponseRedirect with query string. """
    url = reverse(url_name)
    if not get_params:
        return HttpResponseRedirect(url)
    params = urllib.urlencode(get_params)
    full_url = url + "?%s" % params
    log.debug("Redirecting to %s" % full_url)
    return HttpResponseRedirect(full_url)

