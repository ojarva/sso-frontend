from django.http import HttpResponse, HttpResponseRedirect
from utils import custom_redirect
import datetime
import dateutil.parser
import urllib
import logging

log = logging.getLogger(__name__)

def redir_to_sso(request, **kwargs):
    sso = request.GET.get("_sso")
    if sso == "pubtkt":
        log.debug("Redirecting with pubtkt")
        return custom_redirect("login_frontend.providers.pubtkt", request.GET.dict())
    elif sso == "openid":
        log.debug("Redirecting with openid")
        return custom_redirect("login_frontend.providers.openid", request.GET.dict())
    elif sso == "saml":
        log.debug("Redirecting with saml")
        return custom_redirect("login_frontend.providers.saml", request.GET.dict())
    elif sso == "internal":
        log.debug("Redirecting with internal sso")
        return custom_redirect("login_frontend.providers.internal_login", request.GET.dict())
    else:
        log.debug("No sso preference configured")
        if not kwargs.get("no_default", False):
            log.debug("Redirecting back to indexview")
            return custom_redirect("login_frontend.views.indexview", request.GET.dict())
        log.debug("No default configured - return None")
        return None

def get_query_string(mapping, **kwargs):
    for item in kwargs:
        mapping[item] = kwargs[item]
    return urllib.urlencode(mapping)

def is_authenticated(request):
    if request.session.get("relogin_time"):
        return dateutil.parser.parse(request.session.get("relogin_time")) > datetime.datetime.now()
    return False
