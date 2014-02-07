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

