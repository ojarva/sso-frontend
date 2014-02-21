from StringIO import StringIO
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User as DjangoUser
from django.contrib import auth as django_auth
from django.contrib import messages
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseForbidden, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.utils.timesince import timeuntil
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
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
import re
import qrcode
import redis
import time
import urllib
import logging
from django.shortcuts import get_object_or_404
from login_frontend.views import protect_view
from models import CSPReport

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

def test_csp(request, *args, **kwargs):
    return render_to_response("cspreporting/fail.html", {}, context_instance=RequestContext(request))

@protect_view("indexview", required_level=Browser.L_STRONG)
def view_reports(request):
    ret = {}
    entries = CSPReport.objects.filter(username=request.user.username)
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
        b = browsers.get(entry.bid_public)
        if not b:
            try:
                b = Browser.objects.get(bid_public=entry.bid_public)
            except Browser.DoesNotExist:
                pass
        if b:
             entry.browser = b
        entry.linked_source_file = entry.source_file
        if entry.source_file and entry.source_file.startswith("chrome-extension://"):
             extension_id = entry.source_file.replace("chrome-extension://", "")
             if re.match("^\w+$", extension_id):
                 entry.linked_source_file = mark_safe('<a href="https://chrome.google.com/webstore/detail//%s">Chrome extension</a>' % extension_id)

    ret["entries"] = entries

    return render_to_response("cspreporting/view_reports.html", ret, context_instance=RequestContext(request))


@csrf_exempt
def log_report(request, *args, **kwargs):
    csp_data = request.read()
    log.info("%s - %s - %s" % (request.META.get("REMOTE_ADDR"), request.META.get("HTTP_USER_AGENT"), csp_data))

    remote_ip = request.META.get("REMOTE_ADDR")
    bid_public = request.COOKIES.get(Browser.C_BID_PUBLIC)

    if request.browser and request.browser.user:
        username = request.browser.user.username
    else:
        username = None

    try:
        data = json.loads(csp_data)
    except (ValueError, EOFError):
        return HttpResponse("Invalid CSP report.")
    if not "csp-report" in data:
        return HttpResponse("Invalid CSP report: missing csp-report element")

    data = data["csp-report"]
    mandatory_keys = ['blocked-uri', 'document-uri', 'original-policy', 'referrer', 'source-file', 'violated-directive']
    if not all (k in data for k in mandatory_keys):
        return HttpResponse("Invalid CSP report: missing mandatory keys")

    if CSPReport.objects.filter(username=username, bid_public=bid_public).filter(source_file=data.get("source-file"), line_number=data.get("line-number"), violated_directive=data.get("violated-directive")).count() > 0:
        return HttpResponse("Duplicate CSP report. Not stored.")

    report = CSPReport.objects.create(username=username, bid_public=bid_public, csp_raw=csp_data, document_uri=data.get("document-uri"),
                                      referrer=data.get("referrer"), violated_directive=data.get("violated-directive"),
                                      blocked_uri=data.get("blocked-uri"), source_file=data.get("source-file"),
                                      line_number=data.get("line-number"), column_number=data.get("column-number"),
                                      status_code=data.get("status-code"))

    return HttpResponse("OK")


"""

[2014-02-21 15:22:04] INFO [cspreporting.views:58] 10.6.100.129 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) 
Chrome/33.0.1750.117 Safari/537.36 - 
{"csp-report":{"document-uri":"https://login.futurice.com/first/password?_sso=pubtkt&back=https%3A%2F%2Fconfluence.futurice.com%2Fdisplay%2Finfra%2FSetting+up+Mac+OS+X+workstation&timeout=1","referrer":"","violated-directive":"style-src 
'self'","original-policy":"default-src 'none'; connect-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; report-uri /csp-report; font-src 
'self'","blocked-uri":"","source-file":"chrome-extension://iblijlcdoidgdpfknkckljiocdbnlagk","line-number":11,"column-number":16,"status-code":0}}

class CSPReport(models.Model):
    username = models.CharField(max_length=100)
    bid_public = models.CharField(max_length=37) # UUID

    reported_at = models.DateTimeField(auto_now_add=True)

    csp_raw = models.TextField()
    document_uri = models.CharField(max_length=2000, blank=True, null=True)
    referrer = models.CharField(max_length=2000, blank=True, null=True)
    violated_directive = models.CharField(max_length=2000, blank=True, null=True)
    blocked_uri = models.CharField(max_length=2000, blank=True, null=True)
    source_file = models.CharField(max_length=2000, blank=True, null=True)
    line_number = models.IntegerField(null=True, blank=True)
    column_number = models.IntegerField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)

"""
