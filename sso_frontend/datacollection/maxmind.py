from django.conf import settings
import httplib, base64
import json
from django.core.cache import get_cache
import logging

dcache = get_cache("default")

log = logging.getLogger(__name__)

def get_omni_data(ip):
    r_k = "geoip-omni-%s" % ip
    cached = dcache.get(r_k)
    if cached:
        return cached

    headers = {}
    headers["Authorization"] = "Basic {0}".format(base64.b64encode("{0}:{1}".format(settings.MAXMIND_USERID, settings.MAXMIND_PASSWORD)))

    conn = httplib.HTTPSConnection("geoip.maxmind.com")
    conn.request("GET", "/geoip/v2.0/omni/%s" % ip, None, headers)
    resp = conn.getresponse()
    data = json.loads(resp.read())
    dcache.set(r_k, data, 86400 * 60)
    log.info("omni data for %s - %s", ip, data)
    return data
