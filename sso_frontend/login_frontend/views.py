from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.timesince import timeuntil
from django.views.decorators.http import require_http_methods
from dummy import *
from helpers import *
from login_frontend.forms import LoginForm
from ratelimit.decorators import ratelimit
from ratelimit.helpers import is_ratelimited
import time, datetime

@require_http_methods(["GET", "POST"])
@ratelimit(rate='30/15s', ratekey="15s", block=True, method=["POST", "GET"])
@ratelimit(rate='500/10m', ratekey="10m", block=True, method=["POST", "GET"])
@ratelimit(rate='5000/6h', ratekey="6h", block=True, method=["POST", "GET"])
def indexview(request):
    print request.session.keys()
    ret = {}
    if request.session.get("logout", False):
        ret["logout"] = True
        del request.session["logout"]

    back_url = BackUrlValidator(request.GET.get("back", ""), settings.PUBTKT_ALLOWED_DOMAINS)
        
    if request.method == 'POST':
        if request.session.test_cookie_worked():
            request.session.delete_test_cookie()
        else:
            ret["enable_cookies"] = True
        form = LoginForm(request.POST)
        if form.is_valid():
            (username, authenticated) = auth(form.cleaned_data["username"], form.cleaned_data["password"])
            if authenticated:
                ret["valid_login"] = True
                request.session["username"] = username
                request.session["last_username"] = username
                request.session["relogin_time"] = datetime.datetime.now() + datetime.timedelta(hours=6)
                # TODO: sign and set cookie
                if form.cleaned_data["back_url"]:
                    back_url = BackUrlValidator(form.cleaned_data["back_url"], settings.PUBTKT_ALLOWED_DOMAINS)
                    if back_url.invalid:
                        return HttpResponseRedirect("/")
                    return HttpResponseRedirect(back_url.url)
            else:
                ret["authentication_failed"] = True
    else:
        form = LoginForm()
        if request.GET.get("unauth"):
            ret["unauth"] = True
        elif is_authenticated(request) and not back_url.invalid:
            return HttpResponseRedirect(back_url.url)
        elif request.session.get("last_username"):
            form.initial["username"] = request.session.get("last_username")
    
        if request.GET.get("back"):
            ret["destination_host"] = back_url.hostname
            if back_url.invalid:
                ret["server_not_allowed"] = True
            else:
                form.initial["back_url"] = back_url.url
            
    ret["form"] = form

    request.session.set_test_cookie()
    if is_authenticated(request):
        template_name = "signed_in.html"
        ret["username"] = request.session.get("username")
        ret["login_expire"] = timeuntil(request.session.get("relogin_time"))
    else:
        template_name = "sign_in.html"
    return render_to_response(template_name, ret, context_instance=RequestContext(request))


@require_http_methods(["GET", "POST"])
@ratelimit(rate='15/15s', ratekey='15s', block=True, method=["POST", "GET"], skip_if=is_authenticated)
def logoutview(request):
    ret = {}
    do_logout = False
    if request.method == 'POST' or request.GET.get("get_accepted"):
        do_logout = True
        if logout():
            logout_keys = ["username", "authenticated", "authentication_level", "login_time", "relogin_time"]
            for keyname in logout_keys:
                try:
                    del request.session[keyname]
                except KeyError:
                    pass
        request.session["logout"] = True
        return HttpResponseRedirect("/")
    else:
        return HttpResponseRedirect("/")
