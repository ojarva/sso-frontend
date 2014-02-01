from django.core.exceptions import ObjectDoesNotExist
from models import Browser
from django.core.urlresolvers import reverse
import urllib
from django.http import HttpResponse, HttpResponseRedirect

def custom_redirect(url_name, get_params = None):
    url = reverse(url_name)
    if not get_params:
        return HttpResponseRedirect(url)
    params = urllib.urlencode(get_params)
    return HttpResponseRedirect(url + "?%s" % params)

def get_browser(request):
    """ Returns Browser object or None """
    bid = request.COOKIES.get('browserid')
    if not bid: return None
    try:
        browser = Browser.objects.get(bid=bid)
        return browser
    except ObjectDoesNotExist:
        return None
