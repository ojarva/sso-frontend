from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from login_frontend.models import Browser # cookie name
import logging
import time

timing_log = logging.getLogger("request_timing")


def log_request_timing(phase, request):
    timing_log.info("%s: %.5f - %s - %s - [%s] - [bid_public=%s]", phase, time.time(), request.remote_ip, request.get_full_path(), request.META.get("HTTP_USER_AGENT"), request.COOKIES.get(Browser.C_BID_PUBLIC))


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
