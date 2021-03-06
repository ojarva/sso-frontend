#pylint: disable-msg=C0301
"""
Views for SSO service frontend.

This does not include error views (see error_views.py) or admin UI (see admin_frontend module).
"""

from StringIO import StringIO
from io import BytesIO
from django.conf import settings
from django.contrib import messages
from django.core.cache import get_cache
from django.core.mail import mail_admins
from django.core.urlresolvers import reverse
from django.core.validators import validate_email
from django.db.models import Q
from django.http import HttpResponseForbidden, HttpResponse, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods
from django_statsd.clients import statsd as sd
from django_statsd.views import record as django_statsd_navigation_timing
from login_frontend.authentication_views import protect_view
from login_frontend.models import *
from login_frontend.providers import pubtkt_logout
from login_frontend.emails import new_authenticator_notify, new_emergency_generated_notify
from login_frontend.utils import get_geoip_string, redirect_with_get_params, redir_to_sso, paginate, check_browser_name, store_location_caching, get_ratelimit_keys
from ratelimit.decorators import ratelimit
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from validate_yubikey import *
import datetime
import json
import logging
import math
import os
import simplekml
import pyotp
import qrcode
import re
import redis
import sys
import textwrap
import time
import urllib
import urlparse
import PIL, PIL.ImageFont, PIL.ImageDraw, PIL.Image

dcache = get_cache("default")
ucache = get_cache("user_mapping")
user_cache = get_cache("users")
bcache = get_cache("browsers")

log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger("users.%s" % __name__)


@sd.timer("login_frontend.views.custom_log")
def custom_log(request, message, **kwargs):
    """ Automatically logs username, remote IP and bid_public """
    try:
        raise Exception
    except:
        stack = sys.exc_info()[2].tb_frame.f_back
    if stack is not None:
        stack = stack.f_back
    while hasattr(stack, "f_code"):
        co = stack.f_code
        filename = os.path.normcase(co.co_filename)
        filename = co.co_filename
        lineno = stack.f_lineno
        co_name = co.co_name
        break

    level = kwargs.get("level", "info")
    method = getattr(user_log, level)
    remote_addr = request.remote_ip
    bid_public = username = ""
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("[%s:%s:%s] %s - %s - %s - %s", filename, lineno, co_name,
                            remote_addr, username, bid_public, message)

# There's no need to ratelimit this, as ratelimiting takes more resources than what is already happening here.
@require_http_methods(["GET", "POST"])
def main_redir(request):
    """ Hack to enable backward compatibility with pubtkt.
    If "back" parameter is specified, forward to pubtkt provider. Otherwise, go to index page
    """
    if request.GET.get("back") != None:
        custom_log(request, "Redirecting to pubtkt provider from main: %s" % request.GET.dict(), level="debug")
        return redirect_with_get_params("login_frontend.providers.pubtkt", request.GET)
    return redirect_with_get_params("login_frontend.views.indexview", request.GET)


@require_http_methods(["POST", "GET"])
@ratelimit(rate='30/5s', ratekey='5s_timing', block=True, method=["POST"], keys=get_ratelimit_keys)
def timing_report(request):
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
    else:
        bid_public = None

    if request.method == 'POST':
        custom_log(request, "Logging request timing (POST): %s - %s" % (time.time(), request.POST.dict()))
    else:
        if request.GET.get("client") == "boomerang" and bid_public:
            bcache.set("boomerang-done-%s" % bid_public, time.time(), 3600)
        custom_log(request, "Logging request timing (GET): %s - %s" % (time.time(), request.GET.dict()))
    return django_statsd_navigation_timing(request)

@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="5s_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("indexview", required_level=Browser.L_BASIC)
def indexview(request):
    """ Index page: user is redirected
    here if no real destination is available. """

    # TODO: "valid until"
    ret = {}

    user = request.browser.user
    browser = request.browser

    if request.method == "POST":
        if request.POST.get("my_computer"):
            save_browser = False
            if request.POST.get("my_computer") == "on":
                save_browser = True
            if browser.save_browser != save_browser:
                browser.save_browser = save_browser
                browser.save()
                if save_browser:
                    custom_log(request, "Marked browser as remembered", level="info")
                    add_user_log(request, "Marked browser as remembered", "eye")
                    messages.info(request, "You're now remembered on this browser")
                else:
                    custom_log(request, "Marked browser as not remembered", level="info")
                    add_user_log(request, "Marked browser as not remembered", "eye-slash")
                    messages.info(request, "You're no longer remembered on this browser")
                return redirect_with_get_params("login_frontend.views.indexview", request.GET.dict())

    ret["username"] = user.username
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["user_services"] = UserService.objects.filter(user=user).order_by("-access_count")[0:5]
    if user.password_expires:
        if user.password_expires > timezone.now():
            diff = user.password_expires - timezone.now()
            if diff < datetime.timedelta(days=14):
                custom_log(request, "Password is expiring in %s. Show warning" % diff, level="info")
                ret["password_expiring"] = user.password_expires
        else:
            custom_log(request, "Password has expired. Sign user out.", level="warn")
            browser.logout()
            return redirect_with_get_params("login_frontend.views.indexview", request.GET)

    auth_level = request.browser.get_auth_level()
    if user.emulate_legacy:
        ret["auth_level"] = "emulate_legacy"
        ret["session_expire"] = browser.auth_level_valid_until
    elif auth_level == Browser.L_STRONG:
        ret["auth_level"] = "strong"
    elif auth_level == Browser.L_STRONG_SKIPPED:
        ret["auth_level"] = "strong_skipped"
    elif auth_level == Browser.L_BASIC:
        ret["auth_level"] = "basic"
    ret["remembered"] = browser.save_browser
    ret["should_timesync"] = browser.should_timesync()

    response = render_to_response("login_frontend/indexview.html", ret, context_instance=RequestContext(request))
    return response

@ratelimit(rate='80/5s', ratekey="5s_ping", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_ping", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_ping", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@require_http_methods(["GET"])
def automatic_ping(request, **kwargs):
    """ Handles browser queries, and updates browser status when required. """
    location = request.GET.get("location")
    if location:
        if hasattr(request, "browser") and request.browser:
            bcache.set("last-known-location-%s" % request.browser.bid_public, location, 3600)
            bcache.set("last-known-location-timestamp-%s" % request.browser.bid_public, time.time(), 3600)
            bcache.set("last-known-location-from-%s" % request.browser.bid_public, request.remote_ip, 3600)
        activity = request.GET.get("activity")
        hidden = request.GET.get("hidden")
        error = request.GET.get("error")
        client_t = request.GET.get("t")
        client_c = request.GET.get("c")
        client_r = request.GET.get("r")
        client_u = request.GET.get("u")
        if error:
            custom_log(request, "Ping: an error occured: %s - %s" % (location, error), level="error")
        custom_log(request, "Ping from %s - %s - %s - %s - %s - %s - %s" % (location, activity, hidden, client_t, client_c, client_r, client_u))
    ret = {}
    sign_out = False
    if not request.browser:
        # TODO: check whether browser thinks it's still signed in.
        pass
    elif request.browser.forced_sign_out and not request.GET.get("forced_sign_out"):
        # User is not authenticated. If the browser thinks otherwise, fix that.
        ret["not_signed_in"] = True
        ret["redirect_location"] = reverse("login_frontend.views.indexview")+"?forced_sign_out=true"
        sign_out = True

    if kwargs.get("img"):
        #response = HttpResponse(open(settings.PROJECT_ROOT+"/static/img/clear.gif").read(), content_type="image/gif")
        response = HttpResponse()
        response.status_code = 204
        response.reason_phrase = "No Content"
    else:
        response = HttpResponse(json.dumps(ret), content_type="application/json")
        if kwargs.get("external") and request.GET.get("location"):
            try:
                parsed = urlparse.urlparse(request.GET.get("location"))
                if parsed.hostname.endswith(".futurice.com"):
                    response["Access-Control-Allow-Origin"] = "https://"+parsed.hostname
            except:
                pass
    if sign_out:
        pubtkt_logout(request, response)
    return response

@require_http_methods(["GET"])
@ratelimit(rate='5/5s', ratekey="5s", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='60/1m', ratekey="1m", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='500/6h', ratekey="6h", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
def get_pubkey(request, **kwargs):
    service = kwargs.get("service")
    if service == "pubtkt":
        filename = settings.PUBTKT_PUBKEY
    elif service == "saml":
        filename = settings.SAML_PUBKEY
    else:
        raise Http404
    response = HttpResponse(open(filename).read(), content_type="application/x-x509-ca-cert")
    return response


@require_http_methods(["GET"])
@ratelimit(rate='20/5s', ratekey="5s_timesync", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_timesync", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_timesync", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
def timesync(request, **kwargs):
    """ Calculates difference between server and client timestamps.
    timesync.js generates random id, which is used to detect page
    reloads. Round-trip timestamps are stored in redis lists,
    with relatively short expire time (30s). Therefore, there's
    no need to clean up already calculated timesyncs.
    """
    ret = {}
    browser_random = kwargs.get("browser_random")
    redis_id = browser_random

    if not "browser_timezone" in kwargs:
        return render_to_response("login_frontend/timesync.html", {}, context_instance=RequestContext(request))

    browser = None
    if hasattr(request, "browser") and request.browser:
        browser = request.browser
        redis_id = browser.bid_public

    browser_timezone = kwargs.get("browser_timezone")
    browser_time = kwargs.get("browser_time")
    try:
        browser_time = int(browser_time)
    except ValueError:
        browser_time = None
    server_time = kwargs.get("last_server_time")
    recv_time = int(time.time() * 1000)

    def report():
        browser_times = []
        recv_times = []
        while True:
            val = r.lpop(r_k+"browser_time")
            if val is None:
                break
            browser_times.append(int(val))
            val = r.lpop(r_k+"recv_time")
            recv_times.append(int(val))
        if len(recv_times) < 2:
            ret["no_values"] = True
            return
        best_sync = None
        smallest_rtt = None
        errors = []
        for i, _ in enumerate(browser_times):
            if i == 0:
                continue
            bt = browser_times[i]
            rt = recv_times[i]
            rtt = (recv_times[i] - recv_times[i-1]) / 2
            clock_off = rt - bt - rtt
            errors.append(clock_off)
            if smallest_rtt is None or rtt < smallest_rtt:
                best_sync = clock_off
                smallest_rtt = rtt
        def avg(d): return float(sum(d)) / len(d)
        avg_err = avg(errors)
        variance = map(lambda x: (x - avg_err)**2, errors)
        ret["errors_std"] = math.sqrt(avg(variance))
        ret["errors"] = errors
        ret["best_sync"] = best_sync
        ret["report"] = render_to_string("login_frontend/snippets/timesync_results.html", {"best_sync": round(best_sync, 2), "std": round(ret["errors_std"], 2), "meaningful": abs(best_sync) > ret["errors_std"]})
        if browser:
            BrowserTime.objects.create(browser=browser, timezone=browser_timezone, time_diff=best_sync, measurement_error=ret["errors_std"])
            bcache.set("timesync-at-%s" % browser.bid_public, int(time.time()*1000), 60*60*12)
        custom_log(request, "Browser timesync: %s ms with +-%s error. bt: %s; rt: %s" % (best_sync, ret["errors_std"], browser_times, recv_times), level="info")

    r_k = "timesync-%s-" % redis_id
    r.rpush(r_k+"browser_time", browser_time)
    r.rpush(r_k+"recv_time", recv_time)
    r.expire(r_k+"browser_time", 30)
    r.expire(r_k+"recv_time", 30)

    if kwargs.get("command") == "results":
        report()

    ret["browser_time"] = float(browser_time)
    ret["server_time"] = int(time.time() * 1000)
    response = HttpResponse(json.dumps(ret), content_type="application/json")
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='30/5s', ratekey="5s_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("sessions", required_level=Browser.L_STRONG)
def sessions(request):
    """ Shows sessions to the user. """
    user = request.browser.user
    ret = {}
    if request.method == "POST":
        if request.POST.get("logout"):
            bid_public = request.POST.get("logout")
            if bid_public == "all":
                # Log out all sessions
                custom_log(request, "sessions: user requested signing out all sessions", level="info")
                bid_public = [obj.bid_public for obj in Browser.objects.filter(user=user).exclude(bid_public=request.browser.bid_public)]
            else:
                bid_public = [bid_public]

            custom_log(request, "sessions: signing out sessions: %s" % bid_public, level="debug")

            self_logout = False
            for bid in bid_public:
                try:
                    browser_logout = Browser.objects.get(bid_public=bid)
                    if browser_logout.user != user:
                        custom_log(request, "sessions: Tried to sign out browser that belongs to another user: %s" % bid, level="warn")
                        ret["message"] = "That browser belongs to another user."
                    else:
                        if browser_logout == request.browser:
                            custom_log(request, "sessions: signing out current browser", level="info")
                            self_logout = True
                        browser_identification = browser_logout.get_readable_ua()
                        if browser_logout.name:
                            browser_identification = "%s (%s)" % (browser_logout.name, browser_identification)
                        request_browser_identification = request.browser.get_readable_ua()
                        if request.browser.name:
                            request_browser_identification = "%s (%s)" % (request.browser.name, request_browser_identification)

                        browser_logout.logout()
                        browser_logout.forced_sign_out = True
                        browser_logout.save()

                        custom_log(request, "sessions: Signed out browser %s" % browser_logout.bid_public, level="info")
                        add_user_log(request, "Signed out browser %s" % browser_identification, "sign-out")
                        if not self_logout:
                            add_user_log(request, "Signed out from browser %s" % request_browser_identification, "sign-out", bid_public=browser_logout.bid_public)
                        messages.success(request, "Signed out browser %s" % browser_identification)
                except Browser.DoesNotExist:
                    ret["message"] = "Invalid browser"

            if self_logout:
                get_params = request.GET.dict()
                get_params["logout"] = "on"
                return redirect_with_get_params("login_frontend.views.logoutview", get_params)

        elif request.POST.get("action") == "rename":
            try:
                abrowser = Browser.objects.get(bid_public=request.POST.get("bid_public"))
                if abrowser.user != request.browser.user:
                    raise Browser.DoesNotExist

            except Browser.DoesNotExist:
                messages.warning(request, "Invalid browser. Your changes were not saved")
                return redirect_with_get_params("login_frontend.views.sessions", request.GET)
            val = request.POST.get("name")
            abrowser.name = val
            abrowser.save()
            if val:
                messages.success(request, "Browser was renamed as '%s'" % val)
            else:
                messages.success(request, "Browser name was removed")
        return redirect_with_get_params("login_frontend.views.sessions", request.GET)

    browsers = Browser.objects.filter(user=user)
    sessions = []
    for browser in browsers:
        session = BrowserUsers.objects.get(user=user, browser=browser)
        details = {"session": session, "browser": browser}
        if browser == request.browser:
            details["this_session"] = True
        details["geo"] = get_geoip_string(session.remote_ip)
        details["icons"] = browser.get_ua_icons()

        try:
            details["p0f"] = BrowserP0f.objects.filter(browser=browser).latest()
        except BrowserP0f.DoesNotExist:
            pass

        try:
            details["timesync"] = BrowserTime.objects.filter(browser=browser).latest()
        except BrowserTime.DoesNotExist:
            pass

        logins = BrowserLogin.objects.filter(user=user, browser=browser).filter(can_logout=False).filter(signed_out=False).filter(Q(expires_at__gte=timezone.now()) | Q(expires_at=None)).filter(expires_at__lte=timezone.now()+datetime.timedelta(days=30))
        details["logins"] = logins
        cache_keys = [("last_known_location", "last-known-location-%s"), ("last_known_location_from", "last-known-location-from-%s"), ("last_known_location_timestamp", "last-known-location-timestamp-%s")]
        for tk, k in cache_keys:
            r_k = k % browser.bid_public
            val = bcache.get(r_k)
            if val:
                if tk == "last_known_location_timestamp":
                    val = datetime.datetime.fromtimestamp(float(val))
                details[tk] = val

        sessions.append(details)
    try:
        sessions.sort(key=lambda item:item.get("session").last_seen, reverse=True)
    except Exception, e:
        # In certain cases, session.last_seen is None.
        custom_log(request, "Unable to sort sessions: %s" % e, level="error")
    ret["sessions"] = sessions
    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["should_timesync"] = request.browser.should_timesync()
    response = render_to_response("login_frontend/sessions.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET"])
@ratelimit(rate='80/5s', ratekey="5s_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("view_log", required_level=Browser.L_STRONG)
def view_log(request, **kwargs):
    """ Shows log entries to the user """
    ret = {}

    browsers = {}
    ret["browsers"] = []
    list_of_browsers = Log.objects.filter(user=request.browser.user).order_by("bid_public").values("bid_public").distinct()
    for item in list_of_browsers:
        try:
            browser_item = Browser.objects.get(bid_public=item["bid_public"])
        except Browser.DoesNotExist:
            continue
        browsers[item["bid_public"]] = browser_item
        ret["browsers"].append(browser_item)

    entries = Log.objects.filter(user=request.browser.user).order_by("-timestamp")
    bid_public = kwargs.get("bid_public")
    if bid_public:
        entries = entries.filter(bid_public=bid_public)
        try:
            ret["this_browser"] = Browser.objects.get(bid_public=bid_public)
        except Browser.DoesNotExist:
            pass

    entries = paginate(request, entries)

    for entry in entries:
        browser = browsers.get(entry.bid_public)
        if not browser:
            try:
                browser = Browser.objects.get(bid_public=entry.bid_public)
                browsers[entry.bid_public] = browser
            except Browser.DoesNotExist:
                pass
        entry.browser = browser

    ret["entries"] = entries

    response = render_to_response("login_frontend/view_log.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["POST"])
@ratelimit(rate='2/5s', ratekey="5s_location", block=True, method=["POST", "GET"])
@ratelimit(rate='10/1m', ratekey="1m_location", block=True, method=["POST", "GET"])
@ratelimit(rate='250/6h', ratekey="6h_location", block=True, method=["POST", "GET"])
def store_location(request):
    if request.method == 'POST':
        custom_log(request, "Location info posted: %s" % request.POST.dict(), level="debug")
        if not (hasattr(request, "browser") and request.browser):
            custom_log(request, "No browser in request. Not storing location info", level="warn")
            return HttpResponse("No browser available")
        return store_location_caching(request, request.POST.dict())
    return HttpResponse("Invalid request")

@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="5s_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("name_your_browser", required_level=Browser.L_STRONG)
def name_your_browser(request):
    if request.method == 'POST':
        browser_name = request.POST.get("name", "").strip()

        if browser_name and browser_name != request.browser.name:
            if check_browser_name(browser_name):
                custom_log(request, "Set browser name to '%s'" % browser_name, level="info")
                add_user_log(request, "Set browser name to '%s'" % browser_name, "info")
                request.browser.name = browser_name
                request.browser.save()
            else:
                custom_log(request, "Browser name '%s' was rejected." % browser_name, level="info")
        custom_log(request, "Sending auth_state_changed", level="debug")
        if request.GET.get("_sc"):
            request.browser.auth_state_changed()
        return redir_to_sso(request)
    ret = {}
    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("login_frontend/name_browser.html", ret, context_instance=RequestContext(request))
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='5/3s', ratekey="5s_bug", block=True, method=["POST", "GET"])
@ratelimit(rate='30/1m', ratekey="1m_bug", block=True, method=["POST", "GET"])
@ratelimit(rate='500/6h', ratekey="6h_bug", block=True, method=["POST", "GET"])
def report_problem(request):
    ret = {}
    if request.method == 'POST':
        email = request.POST.get("email")
        description = request.POST.get("description")
        please_reply = request.POST.get("please_reply", False)
        feelings = request.POST.get("feelings")
        if hasattr(request, "browser") and request.browser:
            # Don't use browser ID user provided - it either matches request.browser or is completely bogus.
            bid_public = request.browser.bid_public
        else:
            bid_public = "-"
        ret["email"] = email
        ret["description"] = description
        ret["please_reply"] = please_reply
        dont_send = False
        try:
            validate_email(email)
        except:
            if please_reply:
                dont_send = True
                messages.warning(request, "If you want a reply to your report, please enter proper email address")
        if not dont_send:
            ret["report_sent"] = True
            contents = "%s: feelings %s with %s. [%s] reply.\n\n%s" % (email, feelings, bid_public, please_reply, description)
            mail_admins("Bug report from login service", contents)
            custom_log(request, "Received feedback from user: %s" % contents, level="warn")
    return render_to_response("login_frontend/report_problem.html", ret, context_instance=RequestContext(request))


@require_http_methods(["GET", "POST"])
@ratelimit(rate='80/5s', ratekey="5s_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='300/1m', ratekey="1m_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='5000/6h', ratekey="6h_auth", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("configure", required_level=Browser.L_STRONG)
def configure(request):
    """ Configuration view for general options. """
    user = request.browser.user
    ret = {}
    get_params = request.GET.dict()

    ret["user"] = user
    ret["get_params"] = urllib.urlencode(request.GET)
    ret["csp_violations"] = dcache.get("csp-has-reports-for-%s" % user.username)
    ret["authenticator_id"] = user.get_authenticator_id()
    emergency_codes = user.get_emergency_codes()
    ret["emergency_codes"] = emergency_codes
    ret["user_aliases"] = user.get_aliases()
    ret["yubikey"] = user.yubikey

    locations = UserLocation.objects.filter(user=user).count()
    if locations > 0:
        ret["locations_shared"] = locations

    back_url = redir_to_sso(request, no_default=True)
    if back_url:
        ret["back_url"] = back_url.url

    if request.method == "POST":
        if request.POST.get("otp_code"):
            otp = request.POST.get("otp_code")
            (status, message) = request.browser.user.validate_authenticator_code(otp, request)
            if status:
                # Correct OTP.
                user.strong_configured = True
                user.strong_authenticator_used = True
                user.strong_skips_available = 0
                user.save()
                custom_log(request, "configure: validated Authenticator code", level="info")
                add_user_log(request, "Successfully validated Authenticator configuration", "gear")
                messages.success(request, "Successfully validated Authenticator configuration")
            else:
                if message:
                    messages.warning(request, message)
        if request.POST.get("always_sms") == "on":
            add_user_log(request, "Switched to SMS authentication", "info")
            custom_log(request, "cstrong: Switched to SMS authentication", level="info")
            user.strong_configured = True
            user.strong_sms_always = True
            user.strong_skips_available = 0
            user.save()
            messages.success(request, "Switched to SMS authentication")
        elif request.POST.get("always_sms") == "off":
            add_user_log(request, "Switched to Authenticator authentication", "info")
            custom_log(request, "cstrong: Switched to Authenticator authentication", level="info")
            # This is only visible when Authenticator is already generated. If it was not generated,
            # user can click to "Use SMS instead"
            user.strong_configured = True
            user.strong_sms_always = False
            user.strong_skips_available = 0
            user.save()
            messages.success(request, "Default setting changed to Authenticator")
        elif request.POST.get("location"):
            action = request.POST.get("location")
            if action == "share":
                if not user.location_authorized:
                    user.location_authorized = True
                    custom_log(request, "Enabled location sharing", level="info")
                    add_user_log(request, "Enabled location sharing", "location-arrow")
            elif action == "off":
                if user.location_authorized:
                    user.location_authorized = False
                    custom_log(request, "Disabled location sharing", level="info")
                    add_user_log(request, "Disabled location sharing", "location-arrow")
                    messages.success(request, "Location sharing is now disabled")
            elif action == "error":
                custom_log(request, "Encountered error with location sharing settings: %s" % request.POST.get("location-error"), level="warn")
            user.save()
        elif request.POST.get("generate_emergency"):
            (emergency_codes, _) = EmergencyCodes.objects.get_or_create(user=request.browser.user)
            old_existed = False
            if emergency_codes.valid():
                # Old codes existed.
                custom_log(request, "Overwrote old emergency codes", level="info")
                old_existed = True
                pass
            emergency_codes.generate_codes(3)
            custom_log(request, "Created new emergency codes", level="info")
            add_user_log(request, "Generated new emergency codes", "fire-extinguisher")
            dl_uuid = create_browser_uuid()
            dcache.set("emergency-nonce-for-%s" % request.browser.bid_public, dl_uuid, 300)
            ret["dl_uuid"] = dl_uuid
            ret["code_valid_until"] = timezone.now() + datetime.timedelta(seconds=300)
            return render_to_response("login_frontend/emergency_codes_created.html", ret, context_instance=RequestContext(request))
        return redirect_with_get_params("login_frontend.views.configure", get_params)


    response = render_to_response("login_frontend/configure.html", ret, context_instance=RequestContext(request))
    return response

@require_http_methods(["GET"])
@ratelimit(rate='3/5s', ratekey="5s_low", block=True, method=["POST", "GET"])
@ratelimit(rate='20/1m', ratekey="1m_low", block=True, method=["POST", "GET"])
@ratelimit(rate='100/6h', ratekey="6h_low", block=True, method=["POST", "GET"])
@protect_view("get_authenticator_qr", required_level=Browser.L_STRONG)
def get_authenticator_qr(request, **kwargs):
    """ Outputs QR code for Authenticator. Uses single_use_code to prevent
    reloading / linking. """
    if not bcache.get("%s-authenticator_qr_nonce" % request.browser.bid_public) == kwargs["single_use_code"]:
        custom_log(request, "qr: Invalid one-time code for QR. Referrer: %s" % request.META.get("HTTP_REFERRER"), level="warn")
        return HttpResponseForbidden(open(settings.PROJECT_ROOT + "/static/img/invalid_nonce.png").read(), mimetype="image/png")

    if not request.browser.user.strong_authenticator_secret:
        custom_log(request, "qr: Valid qr_nonce, but authenticator_secret is None", level="error")
        return HttpResponseForbidden(open(settings.PROJECT_ROOT + "/static/img/valid_nonce_no_secret.png").read(), mimetype="image/png")

    # Delete QR nonce to prevent replay.
    bcache.delete("%s-authenticator_qr_nonce" % request.browser.bid_public)

    totp = pyotp.TOTP(request.browser.user.strong_authenticator_secret)
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=20, border=0)
    qr.add_data(totp.provisioning_uri(request.browser.user.strong_authenticator_id, "Futurice"))
    img = qr.make_image()
    stringio = StringIO()
    img.save(stringio)
    stringio.seek(0)

    custom_log(request, "qr: Downloaded Authenticator secret QR code", level="info")
    return HttpResponse(stringio.read(), content_type="image/png")


@require_http_methods(["GET"])
@ratelimit(rate='3/5s', ratekey="5s_low", block=True, method=["POST", "GET"])
@ratelimit(rate='20/1m', ratekey="1m_low", block=True, method=["POST", "GET"])
@ratelimit(rate='100/6h', ratekey="6h_low", block=True, method=["POST", "GET"])
@protect_view("get_emergency_codes_image", required_level=Browser.L_STRONG)
def get_emergency_codes_image(request, **kwargs):
    r_k = "emergency-nonce-for-%s" % request.browser.bid_public
    if dcache.get(r_k) != kwargs["single_use_code"]:
        custom_log(request, "emergency codes: invalid one-time code for output. Referrer: %s" % request.META.get("HTTP_REFERRER"), level="warn")
        response = render_to_response("login_frontend/download_invalid_nonce.html", {}, context_instance=RequestContext(request))
        response.status_code = "403"
        response.reason_phrase = "Forbidden"
        return response
    dcache.delete(r_k)

    codes = request.browser.user.get_emergency_codes()
    if not codes or codes.codes_left() == 0:
        custom_log(request, "Tried to download emergency codes; none available.", level="error")
        raise Http404

    font = PIL.ImageFont.truetype(settings.EMERGENCY_FONT, 17)
    img = PIL.Image.new("RGB", (350, 35 + 10 + 35 * codes.codes_left()), (255,255,255))
    draw = PIL.ImageDraw.Draw(img)
    draw.text((10, 20), str(codes.generated_at), "black", font=font)
    i = 1
    for code in EmergencyCode.objects.all().filter(codegroup=codes).order_by("code_id"):
        draw.text((10, 20 + i * 35), "#%s: %s" % (code.code_id, code.code_val), "black", font=font)
        i += 1
    stringio = StringIO()
    img.save(stringio, "png")
    stringio.seek(0)
    codes.downloaded_at = timezone.now()
    codes.downloaded_with = request.browser
    codes.save()
    response = HttpResponse(stringio.read(), content_type="image/png")
    response['Content-Disposition'] = 'attachment; filename=emergency_codes.png'
    add_user_log(request, "Downloaded emergency codes", "info")
    custom_log(request, "Downloaded emergency codes", level="info")
    new_emergency_generated_notify(request, codes)
    return response

@require_http_methods(["GET"])
@ratelimit(rate='3/5s', ratekey="5s_low", block=True, method=["POST", "GET"])
@ratelimit(rate='20/1m', ratekey="1m_low", block=True, method=["POST", "GET"])
@ratelimit(rate='100/6h', ratekey="6h_low", block=True, method=["POST", "GET"])
def get_locations_kml(request):
    locations = UserLocation.objects.filter(user=request.browser.user).order_by("received_at")
    kml = simplekml.Kml()
    for point in locations:
        kml.newpoint(name=str(point.received_at.strftime("%Y-%m-%d")), coords=[(point.longitude, point.latitude)])

    response = HttpResponse(content_type="application/vnd.google-earth.kml+xml")
    response['Content-Disposition'] = 'attachment; filename=%s-location-data.kml' % request.user.username
    response.write(kml.kml())
    add_user_log(request, "Downloaded location data", "info")
    custom_log(request, "Downloaded location data", level="info")
    return response

@require_http_methods(["GET"])
@ratelimit(rate='3/5s', ratekey="5s_low", block=True, method=["POST", "GET"])
@ratelimit(rate='20/1m', ratekey="1m_low", block=True, method=["POST", "GET"])
@ratelimit(rate='100/6h', ratekey="6h_low", block=True, method=["POST", "GET"])
@protect_view("get_emergency_codes_pdf", required_level=Browser.L_STRONG)
def get_emergency_codes_pdf(request, **kwargs):
    r_k = "emergency-nonce-for-%s" % request.browser.bid_public
    if dcache.get(r_k) != kwargs["single_use_code"]:
        custom_log(request, "emergency codes: invalid one-time code for output. Referrer: %s" % request.META.get("HTTP_REFERRER"), level="warn")
        response = render_to_response("login_frontend/download_invalid_nonce.html", {}, context_instance=RequestContext(request))
        response.status_code = "403"
        response.reason_phrase = "Forbidden"
        return response
    dcache.delete(r_k)

    codes = request.browser.user.get_emergency_codes()
    if not codes or codes.codes_left() == 0:
        custom_log(request, "Tried to download emergency codes; none available.", level="error")
        raise Http404

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4, bottomup=0)
    pdfmetrics.registerFont(TTFont('defaultfont', settings.EMERGENCY_FONT))
    p.setFont('defaultfont', 20)
    # Draw sheet timestamp (UTC) on top.
    p.drawString(100,100, str(codes.generated_at))
    i = 0
    for code in EmergencyCode.objects.all().filter(codegroup=codes).order_by("code_id"):
        # Add space every 5 characters to improve readability.
        formatted_code = " ".join(textwrap.wrap(code.code_val, 5))
        p.drawString(100, 150 + i * 35, "#%s: %s" % (code.code_id, formatted_code))
        i += 1
    codes.downloaded_at = timezone.now()
    codes.downloaded_with = request.browser
    codes.save()

    p.showPage()
    p.save()
    pdf = buffer.getvalue()
    buffer.close()

    response = HttpResponse(content_type="application/pdf")
    response['Content-Disposition'] = 'attachment; filename=emergency_codes.pdf'
    response.write(pdf)
    add_user_log(request, "Downloaded emergency codes", "info")
    custom_log(request, "Downloaded emergency codes", level="info")
    new_emergency_generated_notify(request, codes)
    return response


@require_http_methods(["GET", "POST"])
@ratelimit(rate='10/5s', ratekey="5s_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='80/1m', ratekey="1m_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='1000/6h', ratekey="6h_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("configure_yubikey", required_level=Browser.L_STRONG)
def configure_yubikey(request):
    ret = {}
    ret["get_params"] = urllib.urlencode(request.GET)
    user = request.browser.user
    if request.method != "POST":
        custom_log(request, "cyubi: Tried to enter Yubikey configuration view with GET request. Redirecting back. Referer: %s" % request.META.get("HTTP_REFERRER"), level="info")
        messages.info(request, "You can't access configuration page directly. Please click a link below to configure Yubikey.")
        return redirect_with_get_params("login_frontend.views.configure", request.GET)

    ret["back_url"] = redir_to_sso(request).url

    if request.POST.get("revoke-yubikey"):
        if user.yubikey:
            user.yubikey = None
            user.save()
            messages.success(request, "Your Yubikey is now revoked.")
            custom_log(request, "cyubi: Revoked Yubikey", level="info")
        else:
            messages.success(request, "You don't have Yubikey configured. No changes were made.")

    otp = request.POST.get("otp")
    if otp:
        # validate OTP.
        try:
            validator = YubikeyValidate(otp)
        except BadOtpException:
            custom_log(request, "cyubi: Entered incorrect Yubikey OTP", level="warn")
            messages.warning(request, "Invalid Yubikey OTP. This code should come from your Yubikey. It is not your password or Authenticator/SMS OTP.")
            return render_to_response("login_frontend/configure_yubikey.html", ret, context_instance=RequestContext(request))

        # Unknown Yubikey
        try:
            yubikey = Yubikey.objects.get(public_uid=validator.public_uid)
        except Yubikey.DoesNotExist:
            custom_log(request, "cyubi: Unknown Yubikey. public_uid=%s" % validator.public_uid, level="warn")
            messages.warning(request, "Unknown Yubikey. Please contact IT team to get your Yubikey reconfigured.")
            return render_to_response("login_frontend/configure_yubikey.html", ret, context_instance=RequestContext(request))
 
        # Invalid OTP
        validation_failed = False
        try:
            (internalcounter, timestamp) = validator.validate(validator.public_uid, yubikey.internal_uid, yubikey.secret, yubikey.last_id, yubikey.last_timestamp)
        except IncorrectOtpException:
            validation_failed = True
            custom_log(request, "cyubi: Yubikey private UID does not match.", level="warn")
            messages.warning(request, "Internal error: your Yubikey is configured incorrectly. Please contact IT team.")
        except BadOtpException:
            validation_failed = True
            custom_log(request, "cyubi: Yubikey CRC check failed.", level="warn")
            messages.warning(request, "Internal error: integrity check for your Yubikey failed. Please contact IT team.")
        except ReplayedOtpException:
            validation_failed = True
            custom_log(request, "cyubi: replay detected.", level="warn")
            messages.warning(request, "Do not store Yubikey values. It seems your code was replayed.")
        except DelayedOtpException:
            validation_failed = True
            custom_log(request, "cyubi: delayed code detected.", level="warn")
            messages.warning(request, "Do not store Yubikey values. It seems you entered old code.")

        if yubikey.compromised:
            messages.warning(request, "This key is marked as compromised. Please bring the key to IT team for reconfiguration. You can not use this key before it is reconfigured.")
            validation_failed = True

        if validation_failed:
            return render_to_response("login_frontend/configure_yubikey.html", ret, context_instance=RequestContext(request))

        # If no replay/delays were detected, always save Yubikey values to prevent any replay attacks.
        yubikey.last_id = internalcounter
        yubikey.last_timestamp = timestamp
        yubikey.save()



        associated_users = yubikey.user_set.all()

        if len(associated_users) == 0:
            user.yubikey = yubikey
            user.save()
            custom_log(request, "cyubi: Configured Yubikey with public_uid=%s" % yubikey.public_uid, level="info")
            add_user_log(request, "Successfully configured Yubikey", "gear")
            messages.success(request, "Your Yubikey is now configured. You can use it on your next login - just use it on the Authenticator/SMS form.")
            return redirect_with_get_params("login_frontend.views.configure", request.GET.dict())

        associated_user = associated_users[0] # ForeignKey -> only a single user
        if associated_user == user:
            custom_log(request, "cyubi: user tried to reconfigure their current key", level="info")
            messages.info(request, "You already have this key configured. No changes were made.")
            return redirect_with_get_params("login_frontend.views.configure", request.GET.dict())

        yubikey.compromised = True
        yubikey.save()
        associated_user.yubikey = None
        associated_user.save()

        custom_log(request, "cyubi: user tried to configure key that belonged to %s. Marked as compromised." % associated_user.username, level="error")
        messages.warning(request, "This key belonged to another user. It is now marked as compromised. Please bring the key to IT team for reconfiguration.")

    return render_to_response("login_frontend/configure_yubikey.html", ret, context_instance=RequestContext(request))


@require_http_methods(["GET", "POST"])
@ratelimit(rate='10/5s', ratekey="5s_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='80/1m', ratekey="1m_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@ratelimit(rate='1000/6h', ratekey="6h_config", block=True, method=["POST", "GET"], keys=get_ratelimit_keys)
@protect_view("configure_authenticator", required_level=Browser.L_STRONG)
def configure_authenticator(request):
    """ Google Authenticator configuration view. Only POST requests are allowed. """
    ret = {}
    user = request.browser.user
    if request.method != "POST":
        custom_log(request, "cauth: Tried to enter Authenticator configuration view with GET request. Redirecting back. Referer: %s" % request.META.get("HTTP_REFERRER"), level="info")
        messages.info(request, "You can't access configuration page directly. Please click a link below to configure Authenticator.")
        return redirect_with_get_params("login_frontend.views.configure", request.GET)

    ret["back_url"] = redir_to_sso(request).url

    regen_secret = True
    otp = request.POST.get("otp_code")
    if otp:
        (status, message) = request.browser.user.validate_authenticator_code(otp, request)
        if status:
            # Correct OTP.
            user.strong_configured = True
            user.strong_authenticator_used = True
            user.strong_sms_always = False
            user.strong_skips_available = 0
            user.save()
            custom_log(request, "cauth: Reconfigured Authenticator", level="info")
            add_user_log(request, "Successfully configured Authenticator", "gear")
            messages.success(request, "Successfully configured Authenticator")
            redir = redir_to_sso(request, no_default=True)
            if redir:
                return redir_to_sso(request)
            return redirect_with_get_params("login_frontend.views.configure", request.GET.dict())
        else:
            # Incorrect code. Don't regen secret.
            custom_log(request, "cauth: Entered invalid OTP during Authenticator configuration", level="info")
            add_user_log(request, "Entered invalid OTP during Authenticator configuration", "warning")
            regen_secret = False
            if not re.match("^[0-9]{5,6}$", otp):
                ret["is_invalid_otp"] = True
            ret["invalid_otp"] = message
            messages.warning(request, "Invalid one-time password. Please scroll down to try again.")

    if regen_secret:
        authenticator_secret = user.gen_authenticator()
        # As new secret was generated and saved, authenticator configuration is no longer valid.
        # Similarly, strong authentication is no longer configured, because authenticator configuration
        # was revoked.
        user.strong_authenticator_used = False
        user.strong_configured = False
        user.save()
        add_user_log(request, "Regenerated Authenticator code", "gear")
        custom_log(request, "cauth: Regenerated Authenticator code. Set authenticator_used=False, strong_configured=False", level="info")
        new_authenticator_notify(request)

    ret["authenticator_secret"] = user.strong_authenticator_secret
    ret["authenticator_id"] = user.strong_authenticator_id

    authenticator_qr_nonce = create_browser_uuid()
    bcache.set("%s-authenticator_qr_nonce" % request.browser.bid_public, authenticator_qr_nonce, 600)
    ret["authenticator_qr_nonce"] = authenticator_qr_nonce
    request.browser.save()

    ret["get_params"] = urllib.urlencode(request.GET)
    response = render_to_response("login_frontend/configure_authenticator.html", ret, context_instance=RequestContext(request))
    return response
