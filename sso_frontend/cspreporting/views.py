#pylint: disable-msg=C0301
"""
CSP reporting and report viewing.

Stores reports in database, and outputs Django logging.

In database, only non-duplicate records are added.
"""

from cspreporting.models import CSPReport
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from login_frontend.models import Browser
from login_frontend.views import protect_view
import json
import logging
import re
import redis
import statsd

sd = statsd.StatsClient()
r = redis.Redis()

log = logging.getLogger(__name__)
user_log = logging.getLogger(__name__)

@require_http_methods(["GET"])
def test_csp(request, *args, **kwargs):
    """ Outputs page that violates CSP policy """
    return render_to_response("cspreporting/fail.html", {}, context_instance=RequestContext(request))

@sd.timer("cspreporting.views.view_warnings")
@require_http_methods(["GET"])
@protect_view("indexview", required_level=Browser.L_STRONG, admin_only=True)
def view_warnings(request):
    """ Shows potential misconfigurations """
    ret = {}
    entries = CSPReport.objects.filter(source_file__startswith='http')
    paginator = Paginator(entries, 100)
    page = request.GET.get("page")
    try:
        entries = paginator.page(page)
    except PageNotAnInteger:
        entries = paginator.page(1)
        page = 1
    except EmptyPage:
        entries = paginator.page(paginator.num_pages)
        page = paginator.num_pages
    entries.pagerange = range(1, paginator.num_pages+1)

    browsers = {}

    for entry in entries:
        if entry.bid_public == request.browser.bid_public:
            entry.current_browser = True
        browser = browsers.get(entry.bid_public)
        if not browser:
            try:
                browser = Browser.objects.get(bid_public=entry.bid_public)
                browsers[entry.bid_public] = browser
            except Browser.DoesNotExist:
                pass
        if browser:
            entry.browser = browser
        entry.linked_source_file = entry.source_file

    ret["entries"] = entries

    return render_to_response("cspreporting/view_warnings.html", ret, context_instance=RequestContext(request))


@sd.timer("cspreporting.views.view_reports")
@require_http_methods(["GET"])
@protect_view("indexview", required_level=Browser.L_STRONG)
def view_reports(request):
    """ Report viewing. Only shows records for current user.
    For chrome, extensions are linked to Chrome web store.
    """

    ret = {}
    ret["ausername"] = request.browser.user.username
    entries = CSPReport.objects.filter(username=request.browser.user.username)
    paginator = Paginator(entries, 100)
    page = request.GET.get("page")
    try:
        entries = paginator.page(page)
    except PageNotAnInteger:
        entries = paginator.page(1)
        page = 1
    except EmptyPage:
        entries = paginator.page(paginator.num_pages)
        page = paginator.num_pages
    entries.pagerange = range(1, paginator.num_pages+1)

    browsers = {}

    for entry in entries:
        sd.incr("cspreporting.views.view_reports.load_entry", 1)
        if entry.bid_public == request.browser.bid_public:
            entry.current_browser = True
        browser = browsers.get(entry.bid_public)
        if not browser:
            try:
                browser = Browser.objects.get(bid_public=entry.bid_public)
                browsers[entry.bid_public] = browser
                sd.incr("cspreporting.views.view_reports.get_browser.database", 1)
            except Browser.DoesNotExist:
                pass
        else:
            sd.incr("cspreporting.views.view_reports.get_browser.cache", 1)

        if browser:
            entry.browser = browser
        entry.linked_source_file = entry.source_file
        if entry.source_file and entry.source_file.startswith("chrome-extension://"):
            extension_id = entry.source_file.replace("chrome-extension://", "")
            if re.match("^\w+$", extension_id):
                entry.linked_source_file = mark_safe('<a href="https://chrome.google.com/webstore/detail//%s">Chrome extension</a>' % extension_id)

    ret["entries"] = entries
    return render_to_response("cspreporting/view_reports.html", ret, context_instance=RequestContext(request))


@sd.timer("cspreporting.views.log_report")
@require_http_methods(["GET", "POST"])
@csrf_exempt
def log_report(request, *args, **kwargs):
    """ Logs CSP report. Cookies may or may not be available. """
    sd.incr("cspreporting.views.log_report", 1)
    csp_data = request.read()
    if len(csp_data) < 50 or len(csp_data) > 2000:
        sd.incr("cspreporting.views.log_report.invalid_report", 1)
        return HttpResponse("Invalid CSP report.")

    remote_ip = request.META.get("REMOTE_ADDR")
    bid_public = request.COOKIES.get(Browser.C_BID_PUBLIC)
    log.info("%s - %s - %s - %s", remote_ip, request.META.get("HTTP_USER_AGENT"), bid_public, csp_data)

    if hasattr(request, "browser") and request.browser and request.browser.user:
        username = request.browser.user.username
    else:
        username = None

    try:
        data = json.loads(csp_data)
    except (ValueError, EOFError):
        sd.incr("cspreporting.views.log_report.invalid_json", 1)
        return HttpResponse("Invalid CSP report.")
    if not "csp-report" in data:
        sd.incr("cspreporting.views.log_report.missing_data", 1)
        return HttpResponse("Invalid CSP report: missing csp-report element")

    data = data["csp-report"]
    mandatory_keys = ['blocked-uri', 'document-uri', 'original-policy', 'referrer', 'source-file', 'violated-directive']
    if not all (k in data for k in mandatory_keys):
        sd.incr("cspreporting.views.log_report.missing_mandatory_key", 1)
        return HttpResponse("Invalid CSP report: missing mandatory keys")

    r_k = "csp-recorded-%s-%s-%s-%s-%s" % (username, bid_public, data.get("source-file"), data.get("line-number"), data.get("violated-directive"))

    if r.get(r_k) or CSPReport.objects.filter(username=username, bid_public=bid_public).filter(source_file=data.get("source-file"), 
            line_number=data.get("line-number"), violated_directive=data.get("violated-directive")).count() > 0:

        sd.incr("cspreporting.views.log_report.duplicate", 1)
        return HttpResponse("Duplicate CSP report. Not stored.")

    r.setex(r_k, True, 86400 * 7)

    sd.incr("cspreporting.views.log_report.created", 1)
    a = CSPReport.objects.create(username=username, bid_public=bid_public, csp_raw=csp_data, document_uri=data.get("document-uri"),
                                      referrer=data.get("referrer"), violated_directive=data.get("violated-directive"),
                                      blocked_uri=data.get("blocked-uri"), source_file=data.get("source-file"),
                                      line_number=data.get("line-number"), column_number=data.get("column-number"),
                                      status_code=data.get("status-code"))

    return HttpResponse("OK %s" % a)
