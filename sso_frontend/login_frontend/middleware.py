#pylint: disable-msg=C0301

"""
Middleware classes.

BrowserMiddleware adds request.browser, and automatically signs user out,
if browser was restarted, and not saved.

Also, session cookie is automatically added if it does not exist yet.
"""

from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist, MiddlewareNotUsed
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from login_frontend.models import Browser, BrowserUsers, BrowserLogin, create_browser_uuid
from login_frontend.providers import pubtkt_logout
from login_frontend.utils import dedup_messages
import logging
import re
import time

log = logging.getLogger(__name__)

timing_log = logging.getLogger("request_timing")

DISALLOWED_UA = [
 re.compile("^Wget/.*"),
 re.compile("^Pingdom.com_bot_version.*"),
 re.compile("^curl/.*")
]

__all__ = ["get_browser", "BrowserMiddleware"]

def get_browser_instance(request):
    bid = request.COOKIES.get(Browser.C_BID)
    if not bid:
        return None
    try:
        browser = Browser.objects.get(bid=bid)
    except ObjectDoesNotExist:
        log.info("Unknown browser id '%s' from '%s'", bid, request.META.get("REMOTE_ADDR"))
        return None

    return browser

def get_browser(request):
    browser = get_browser_instance(request)
    if browser is None:
        return None
    bid = browser.bid_public

    if request.path.startswith("/csp-report"):
        log.debug("Browser '%s' from '%s' reporting CSP - skip sign-out processing", bid, request.META.get("REMOTE_ADDR"))
        return browser

    if request.COOKIES.get(Browser.C_BID_SESSION) == browser.bid_session:
        browser.valid_session_bid = True
    else:
        browser.valid_session_bid = False
        # Mark session based logins as signed_out
        sessions = BrowserLogin.objects.filter(browser=browser).filter(expires_session=True).filter(signed_out=False)
        for session in sessions:
            log.info("Marking session %s for %s (user %s) as signed out, after browser session id cookie disappeared.", session.sso_provider, browser.bid, session.user.username)
            session.signed_out = True
            session.save()
        if not browser.save_browser:
            # Browser was restarted, and save_browser is not set. Logout.
            log.info("Browser bid_public=%s was restarted. Logging out. path: %s", browser.bid_public, request.path)
            dedup_messages(request, messages.INFO, "According to our records, your browser was restarted. Therefore, you were signed out.")
            browser.logout(request)

    if browser.user:
        user_to_browser, _ = BrowserUsers.objects.get_or_create(user=browser.user, browser=browser)
        if request.path.startswith("/ping"):
            user_to_browser.remote_ip_passive = request.META.get("REMOTE_ADDR")
            user_to_browser.last_seen_passive = timezone.now()
        else:
            user_to_browser.remote_ip = request.META.get("REMOTE_ADDR")
            user_to_browser.last_seen = timezone.now()
        user_to_browser.save()
    return browser


class BrowserMiddleware(object):
    """ Adds request.browser. """ 

    def process_request(self, request):
        """ Adds request.browser. Filters out monitoring bots. """
        ua = request.META.get("HTTP_USER_AGENT") 
        for ua_re in DISALLOWED_UA:
            if ua_re.match(ua):
                #TODO: futurice
                return HttpResponse("OK. Your request was caught because you seem to be a bot. If this is by mistake, please contact admin@futurice.com")

        request.browser = get_browser(request)


    def process_response(self, request, response):
        """ Automatically adds session cookie if old one is not available. """
        
        # Browser from process_request is not available here.
        browser = get_browser_instance(request)

        if not browser or browser.get_auth_level() < Browser.L_STRONG:
            response = pubtkt_logout(request, response)

        if not browser:
            log.debug("Browser does not exist")
            return response

        if request.COOKIES.get(Browser.C_BID_SESSION) != browser.bid_session:
            # No valid session ID exists. Regen it first.
            browser.bid_session = create_browser_uuid()
            log.info("Session bid does not exist. Regenerating. bid_public=%s" % browser.bid_public)
            browser.save()
            cookies = browser.get_cookie()
            for cookie_name, cookie in cookies:
                response.set_cookie(cookie_name, **cookie)

        return response


def log_request_timing(phase, request):
    timing_log.info("%s: %.5f - %s - %s - [%s] - [bid_public=%s]", phase, time.time(), request.META.get("REMOTE_ADDR"), request.get_full_path(), request.META.get("HTTP_USER_AGENT"), request.COOKIES.get(Browser.C_BID_PUBLIC))
    

class InLoggingMiddleware(object):
    def __init__(self):
        if settings.DISABLE_TIMING_LOGGING:
            raise MiddlewareNotUsed

    def process_request(self, request):
        log_request_timing("process_request.first", request)

class ViewLoggingMiddleware(object):
    def __init__(self):
        if settings.DISABLE_TIMING_LOGGING:
            raise MiddlewareNotUsed

    def process_view(self, request, view_func, view_args, view_kwargs):
        log_request_timing("process_view.last", request)

class OutLoggingMiddleware(object):
    def __init__(self):
        if settings.DISABLE_TIMING_LOGGING:
            raise MiddlewareNotUsed

    def process_response(self, request, response):
        log_request_timing("process_response.last", request)
        return response
