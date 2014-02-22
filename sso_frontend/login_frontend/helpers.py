""" Helper functions """

from django.http import HttpResponse, HttpResponseRedirect
from login_frontend.utils import custom_redirect
import datetime
import dateutil.parser
import urllib
import logging

log = logging.getLogger(__name__)

__all__ = ["redir_to_sso", "is_authenticated"]

def redir_to_sso(request, **kwargs):
    """ Returns HttpResponseRedirect to proper login service. """
    #TODO: these are outdated.

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

def is_authenticated(request):
    """ Returns true if user is authenticated. """
    #TODO: this is outdated.
    if request.session.get("relogin_time"):
        return dateutil.parser.parse(request.session.get("relogin_time")) > datetime.datetime.now()
    return False
