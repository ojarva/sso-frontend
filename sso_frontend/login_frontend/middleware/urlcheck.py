from django_statsd.clients import statsd as sd
from django.template import RequestContext
from django.shortcuts import render_to_response
import logging
import urllib

log = logging.getLogger(__name__)

class UrlCheckMiddleware(object):
    @sd.timer("middleware.UrlCheckMiddleware.process_request")
    def process_request(self, request):
        try:
            urllib.urlencode(request.GET)
        except:
            sd.incr("middleware.UrlCheckMiddleware.invalid_url")
            return render_to_response("login_frontend/errors/invalid_url.html", {}, context_instance=RequestContext(request))
