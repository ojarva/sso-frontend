from django.http import HttpResponse, HttpResponseRedirect
from utils import custom_redirect
import datetime
import dateutil.parser
import urllib

def redir_to_sso(request):
    sso = request.GET.get("_sso")
    if sso == "pubtkt":
        return custom_redirect("login_frontend.providers.pubtkt", request.GET.dict())
    elif sso == "openid":
        return custom_redirect("login_frontend.providers.openid", request.GET.dict())
    elif sso == "saml":
        return custom_redirect("login_frontend.providers.saml", request.GET.dict())
    elif sso == "internal":
        return custom_redirect("login_frontend.providers.internal_login", request.GET.dict())
    else:
        return HttpResponse("Invalid SSO provider")

def get_query_string(mapping, **kwargs):
    for item in kwargs:
        mapping[item] = kwargs[item]
    return urllib.urlencode(mapping)

def is_authenticated(request):
    if request.session.get("relogin_time"):
        return dateutil.parser.parse(request.session.get("relogin_time")) > datetime.datetime.now()
    return False
