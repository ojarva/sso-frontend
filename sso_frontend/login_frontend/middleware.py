from django.core.exceptions import ObjectDoesNotExist
from login_frontend.models import Browser
import logging
log = logging.getLogger(__name__)

def get_browser(request):
    bid = request.COOKIES.get('v2browserid')
    if not bid: return None
    try:
        browser = Browser.objects.get(bid=bid)
        if request.COOKIES.get("v2sessionbid") == browser.bid_session:
            browser.valid_session_bid = True
        else:
            browser.valid_session_bid = False
        return browser
    except ObjectDoesNotExist:
        log.info("Unknown browser id '%s' from '%s'", bid, request.META.get("REMOTE_ADDR"))
        return None


class BrowserMiddleware(object):
    def process_request(self, request):
        request.browser = get_browser(request)

    def process_response(self, request, response):
        # Browser from process_request is not available here.
        browser = get_browser(request)
  
        if not browser:
            return response

        if not browser.valid_session_bid:
            cookies = browser.get_cookie()
            for cookie_name, cookie in cookies:
               response.set_cookie(cookie_name, **cookie)

        return response
