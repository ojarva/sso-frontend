from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from login_frontend.models import Browser, BrowserUsers, BrowserLogin, create_browser_uuid
from login_frontend.providers import pubtkt_logout
import logging

log = logging.getLogger(__name__)

def get_browser(request):
    bid = request.COOKIES.get(Browser.C_BID)
    if not bid: return None
    try:
        browser = Browser.objects.get(bid=bid)
    except ObjectDoesNotExist:
        log.info("Unknown browser id '%s' from '%s'", bid, request.META.get("REMOTE_ADDR"))
        return None

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
            browser.logout(request)

    if browser.user:
        user_to_browser, _ = BrowserUsers.objects.get_or_create(user=browser.user, browser=browser)
        user_to_browser.remote_ip = request.META.get("REMOTE_ADDR")
        user_to_browser.last_seen = timezone.now()
        user_to_browser.save()
    return browser


class BrowserMiddleware(object):
    def process_request(self, request):
        request.browser = get_browser(request)
        if (request.browser and not request.browser.valid_session_bid
                    and not request.browser.save_browser):
            # Browser is not saved, and it was restarted.
            # Ensure everything is removed.
            # Browser ID does not change.
            request.browser.logout(request)

    def process_response(self, request, response):
        # Browser from process_request is not available here.
        browser = get_browser(request)

        if not browser or browser.get_auth_level() < Browser.L_STRONG:
            response = pubtkt_logout(request, response)

        if not browser:
            return response

        if not browser.valid_session_bid:
            # No valid session ID exists. Regen it first.
            browser.bid_session = create_browser_uuid()
            browser.save()
            cookies = browser.get_cookie()
            for cookie_name, cookie in cookies:
               response.set_cookie(cookie_name, **cookie)

        return response
