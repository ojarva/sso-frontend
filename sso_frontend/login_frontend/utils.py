from django.conf import settings
from django.conf import settings
from django.contrib.auth.models import User as DjangoUser
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import timezone
from models import Browser, User
import _slumber_auth
import geoip2
import geoip2.database
import geoip2.errors
import geoip2.models
import ipaddr
import slumber
import urllib
import logging

log = logging.getLogger(__name__)

geo = geoip2.database.Reader(settings.GEOIP_DB)
IP_NETWORKS = settings.IP_NETWORKS

def is_private_net(ip_address):
    """ Returns True if specified in private networks, imported from
        local_settings """
    try:
        ip = ipaddr.IPv4Address(ip_address)
    except:
        return False

    for (network, country, city, description) in IP_NETWORKS:
        if ((isinstance(network, ipaddr.IPv4Address) and
            ip is network) or
           (isinstance(network, ipaddr.IPv4Network) and
            ip in network)):
            return description
    return False


def get_and_refresh_user(username):
    log.info("Refreshing %s" % username)
    api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))
    refresh_user(api.users().get(username=username))

def refresh_user(user):
    username = user.get("username")
    log.info("Updating %s" % username)
    first_name = user.get("first_name")
    last_name = user.get("last_name")
    email = user.get("email", "")
    phone1 = user.get("phone1", "")
    phone2 = user.get("phone2")
    if username is None or email is None:
        log.debug("Username or email is none - skip")
        return
    if first_name is None or last_name is None:
        log.debug("First name or last name is none - skip")
        return

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
    url = reverse(url_name)
    if not get_params:
        return HttpResponseRedirect(url)
    params = urllib.urlencode(get_params)
    full_url = url + "?%s" % params
    log.debug("Redirecting to %s" % full_url)
    return HttpResponseRedirect(full_url)

