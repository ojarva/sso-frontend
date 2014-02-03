from django.utils.functional import SimpleLazyObject
from login_frontend.models import Browser

def get_browser(request):
    bid = request.COOKIES.get('browserid')
    if not bid: return None
    try:
        browser = Browser.objects.get(bid=bid)
        return browser
    except ObjectDoesNotExist:
        return None


class BrowserMiddleware(object):
    def process_request(self, request):
        request.browser = SimpleLazyObject(lambda: get_browser(request))
