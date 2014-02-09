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
        if (request.browser and not request.browser.valid_session_bid
                    and not request.browser.save_browser):
            # Browser is not saved, and it was restarted.
            # Ensure everything is removed.
            # Browser ID does not change.
            request.browser.logout(request)

    def process_response(self, request, response):
        # Browser from process_request is not available here.
        browser = get_browser(request)
  
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
