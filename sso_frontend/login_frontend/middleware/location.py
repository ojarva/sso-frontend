from django_statsd.clients import statsd as sd
from django.core.cache import get_cache
user_cache = get_cache("users")
bcache = get_cache("browsers")

class LocationMiddleware(object):
    @sd.timer("login_frontend.middleware.process_request")
    def process_request(self, request):
        request.ask_location = False
        if not (hasattr(request, "browser") and request.browser):
            return
        browser = request.browser
        if browser.user:
            if bcache.get("location-stored-for-%s-%s" % (request.browser.bid_public, request.browser.user.username)):
                return
            if browser.user.location_authorized:
                request.ask_location = True
                return
        if bcache.get("location-authorized-for-%s" % browser.bid_public):
            request.ask_location = True
            return
