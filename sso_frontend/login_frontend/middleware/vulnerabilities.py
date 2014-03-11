from browser_vulnerabilities import BrowserVulnerability
from django_statsd.clients import statsd as sd
import logging

log = logging.getLogger(__name__)

class VulnerableBrowser(object):
    @sd.timer("VulnerableBrowser.process_request")
    def process_request(self, request):
        request.vulnerability = None
        ua = request.META.get("HTTP_USER_AGENT")
        if ua is None:
            log.warn("Encountered HTTP request with no user agent string")
            return
        try:
            vb = BrowserVulnerability(ua)
            vulnerability = vb.vulnerabilities()
        except Exception, e:
            log.error("Vulnerability matching failed: %s - %s" % (e, ua))
        if vulnerability == False:
            return
        log.info("Browser with vulnerability: %s - %s - %s", request.remote_ip, vulnerability, ua)
        request.vulnerability = vulnerability
