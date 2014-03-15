from django_statsd.clients import statsd as sd
from django.core.cache import get_cache
bcache = get_cache("browsers")

class TimesyncMiddleware(object):
    @sd.timer("TimesyncMiddleware.process_request")
    def process_request(self, request):
        request.should_timesync = False
        bid_public = request.COOKIES.get(Browser.C_BID_PUBLIC)
        if not bid_public:
            return
        last_timesync = bcache.get("timesync-at-%s" % bid_public)
        if not last_timesync:
            request.should_timesync
