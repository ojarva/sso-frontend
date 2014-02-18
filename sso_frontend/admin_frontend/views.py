from StringIO import StringIO
from django.contrib.auth.models import User as DjangoUser
from django.contrib import auth as django_auth
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.timesince import timeuntil
from django.views.decorators.http import require_http_methods
from login_frontend.helpers import *
from login_frontend.models import *
from ratelimit.decorators import ratelimit
from ratelimit.helpers import is_ratelimited
from login_frontend.utils import *
import Cookie
import auth_pubtkt
import datetime
import dateutil.parser
import json
import pyotp
import qrcode
import redis
import time
import urllib
import logging
from django.shortcuts import get_object_or_404
from login_frontend.views import protect_view


log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger(__name__)
def custom_log(request, message, **kwargs):
    level = kwargs.get("level", "info")
    method = getattr(user_log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    if request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("%s - %s - %s - %s", remote_addr, username, bid_public, message)


@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_indexview(request):
    custom_log(request, "Admin: frontpage")
    ret = {}
    ret["users"] = User.objects.all().count()
    ret["browsers"] = Browser.objects.all().count()
    ret["active_logins"] = BrowserLogin.objects.filter(signed_out=False).filter(expires_at__gte=timezone.now()).count()

    ret["num_strong_configured"] = User.objects.filter(strong_configured=True).count()
    ret["num_sms_always"] = User.objects.filter(strong_sms_always=True).count()
    ret["num_authenticator_used"] = User.objects.filter(strong_authenticator_used=True).count()
    ret["num_strong_configured_not_used"] = User.objects.exclude(strong_authenticator_generated_at=None).filter(strong_authenticator_used=False).count()

    active_browsers = Browser.objects.exclude(user=None)
    ret["active_browsers"] = []
    for browser in active_browsers:
        if browser.auth_level_valid_until > timezone.now() and browser.auth_state_valid_until > timezone.now() and browser.auth_level >= Browser.L_STRONG:
            ret["active_browsers"].append(browser)

    ret["last_logins"] = BrowserLogin.objects.all()[0:10]

    ret["admins"] = User.objects.filter(is_admin=True)

    return render_to_response("admin_frontend/indexview.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_users(request):
    custom_log(request, "Admin: users")
    ret = {}
    ret["users"] = User.objects.all().order_by('username')
    return render_to_response("admin_frontend/users.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_userdetails(request, **kwargs):
    ret = {}
    username = kwargs.get("username")
    ret["auser"] = get_object_or_404(User, username=username)
    custom_log(request, "Admin: user details - %s" % username)

    if request.method == "POST":
        if request.POST.get("refresh"):
            custom_log(request, "Admin: refreshed %s" % username)
            get_and_refresh_user(username)
            messages.info(request, "Successfully refreshed: %s" % username)
        elif request.POST.get("signout"):
            custom_log(request, "Admin: sign out %s" % username)
            user = ret["auser"]
            user.sign_out_all(admin_logout=request.browser.user.username)
            log_entry = Log(user=user, message="%s signed out all sessions for this user" % request.browser.user.username, status="exclamation-circle")
            log_entry.save()
            messages.info(request, "Signed out all sessions for %s" % username)

        elif request.POST.get("revoke") == "yes":
            custom_log(request, "Admin: revoked %s" % username)
            user = ret["auser"]
            user.reset()
            user.sign_out_all(admin_logout=request.browser.user.username)
            log_entry = Log(user=user, message="%s revoked strong authentication settings and signed out all sessions" % request.browser.user.username, status="exclamation-circle")
            log_entry.save()
            messages.info(request, "Revoked Authenticator configuration for %s" % username)
        return HttpResponseRedirect("admin_frontend.views.admin_userdetails", (username, ))

    ret["entries"] = Log.objects.filter(user=ret["auser"])[0:100]

    ret["duser"] = get_object_or_404(DjangoUser, username=username)
    ret["browsers"] = Browser.objects.filter(user=ret["auser"])
    ret["logins"] = BrowserLogin.objects.filter(user=ret["auser"])
    return render_to_response("admin_frontend/userdetails.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_logins(request):
    ret = {}
    custom_log(request, "Admin: list of logins")
    ret["logins"] = BrowserLogin.objects.all()
    return render_to_response("admin_frontend/logins.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_browsers(request):
    ret = {}
    custom_log(request, "Admin: list of browsers")
    ret["browsers"] = Browser.objects.all()
    return render_to_response("admin_frontend/browsers.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_browserdetails(request, **kwargs):
    ret = {}
    bid_public = kwargs.get("bid_public")
    ret["abrowser"] = get_object_or_404(Browser, bid_public=bid_public)
    ret["logins"] = BrowserLogin.objects.filter(browser=ret["abrowser"])
    ret["entries"] = Log.objects.filter(bid_public=bid_public)[0:100]
    username = None
    if ret["abrowser"].user:
        username = ret["abrowser"].user.username
    custom_log(request, "Admin: browser details for %s (%s)" % (bid_public, username))
    return render_to_response("admin_frontend/browserdetails.html", ret, context_instance=RequestContext(request))

@protect_view("admin_indexview", required_level=Browser.L_STRONG, admin_only=True)
def admin_logs(request, **kwargs):
    ret = {}
    custom_log(request, "Admin: logs")
    bid_public = kwargs.get("bid_public")
    username = kwargs.get("username")
    if bid_public:
        ret["entries"] = Log.objects.filter(bid_public=bid_public)[0:1000]
        username = None
        try:
            ret["abrowser"] = Browser.objects.get(bid_public=bid_public)
            if ret["abrowser"].user:
                username = ret["abrowser"].user.username
        except Browser.DoesNotExist:
            ret["missing_browser"] = True
        custom_log(request, "Admin: entries for %s (%s)" % (bid_public, username))

    elif username:
        ret["auser"] = get_object_or_404(username=username)
        ret["entries"] = Log.objects.filter(user=ret["auser"])[0:1000]
        custom_log(request, "Admin: entries for %s" % username)
    else:
        custom_log(request, "Admin: all entries")
        ret["entries"] = Log.objects.all()[0:1000]
    return render_to_response("admin_frontend/logs.html", ret, context_instance=RequestContext(request))
