from django import template
register = template.Library()

from login_frontend.utils import get_geoip_string

def ip_to_geoip(ip_address):
    return get_geoip_string(ip_address)

register.filter("ip_to_geoip", ip_to_geoip)
