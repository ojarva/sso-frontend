#pylint: disable-msg=C0301

"""
P0f middleware: logs p0f information for browser.
"""

from django.conf import settings
from django.core.cache import get_cache
from django.core.exceptions import MiddlewareNotUsed
from django.utils import timezone
from django_statsd.clients import statsd as sd
from login_frontend.models import BrowserP0f
import datetime
import logging
import p0f
import socket

bcache = get_cache("browsers")

log = logging.getLogger(__name__)

p0f_log = logging.getLogger("p0f")


__all__ = ["P0fMiddleware"]

class P0fMiddleware(object):
    def __init__(self):
        if settings.P0F_SOCKET is None:
            raise MiddlewareNotUsed

    @sd.timer("P0fMiddleware.process_request")
    def process_request(self, request):
        if request.path.startswith("/timesync"):
            return

        if not hasattr(request, "browser") or not request.browser:
            return

        browser = request.browser
        remote_addr = request.remote_ip
        r_k = "p0f-last-update-%s" % (browser.bid_public)
        last_update = bcache.get(r_k)
        if last_update == remote_addr:
            return
        bcache.set(r_k, remote_addr, 30)

        def update_newest(newest, remote_info):
            if remote_info["uptime_sec"] == None and newest.uptime_sec == None:
                # If both old and new uptimes are None, don't create a new instance.
                return True
            if remote_info["uptime_sec"] == None:
                return False
            if newest.uptime_sec == None:
                return False

            time_since_last = timezone.now() - newest.updated_at
            time_since_last_sec = time_since_last.days * 86400 + time_since_last.seconds

            expected_uptime = newest.uptime_sec + time_since_last_sec

            up_mod_days = remote_info["up_mod_days"]
            if up_mod_days and up_mod_days > datetime.timedelta(days=1):
                # Detect wraparound
                up_mod_sec = up_mod_days.days * 86400

                if expected_uptime > up_mod_sec:
                    log.debug("p0f: %s@%s - uptime wraparound detected: %s", browser.bid_public, remote_addr, expected_uptime)
                    newest.wraparounds += 1
                    expected_uptime -= up_mod_sec

            uptime_diff = expected_uptime - remote_info["uptime_sec"]
            allowed_diff = max(10*60, expected_uptime * 0.1)

            if uptime_diff > allowed_diff:
                log.debug("p0f: %s@%s - uptime went backwards %s seconds", browser.bid_public, remote_addr, uptime_diff)
                return False

            if uptime_diff < -allowed_diff:
                log.debug("p0f: %s@%s - uptime jumped onwards %s seconds", browser.bid_public, remote_addr, uptime_diff)
                return False

            time_since_last = timezone.now() - newest.last_seen

            update_keys = ("total_conn", "uptime_sec", "os_flavor", "os_name", "os_match_q", "distance", "last_seen")
            for k in update_keys:
                setattr(newest, k, remote_info[k])
            log.debug("p0f: updated %s", browser.bid_public)
            newest.save()
            return True

        try:
            p0fapi = p0f.P0f(settings.P0F_SOCKET)
            try:
                sd.incr("p0f.queried", 1)
                remote_info = p0fapi.get_info(remote_addr)
                request.p0f = remote_info
                sd.incr("p0f.fetched", 1)
            except KeyError, e:
                # No information exists.
                sd.incr("p0f.error.no_info", 1)
                log.debug("p0f: %s", str(e))
                return
            except (ValueError, p0f.P0fException), e:
                # Invalid information received from p0f
                sd.incr("p0f.error.invalid", 1)
                log.error("p0f raised KeyError: %s", str(e))
                return

            username = None
            if browser.user:
                username = browser.user.username

            p0f_log.info("%s - %s - %s - %s - %s", remote_addr, browser.bid_public, username, request.path, str(remote_info))

            if remote_info["last_nat"] != None:
                # NAT detected. Don't store/update anything.
                sd.incr("p0f.nat", 1)
                log.debug("p0f: %s@%s - NAT detected", browser.bid_public, remote_addr)
                return

            try:
                newest = BrowserP0f.objects.filter(browser=browser).latest()
            except BrowserP0f.DoesNotExist:
                newest = None

            updated = False
            if newest:
                # Update this if uptime_diff matches, otherwise create a new object.
                updated = update_newest(newest, remote_info)
                log.debug("p0f: %s@%s - update_newest returned %s", browser.bid_public, remote_addr, updated)

            if not updated:
                data = {"browser": browser}
                for k in ("first_seen", "last_seen", "total_conn", "uptime_sec", "last_nat", "distance", "os_match_q", "os_name", "os_flavor", "link_type"):
                    data[k] = remote_info[k]
                if remote_info["up_mod_days"]:
                    data["up_mod_days"] = remote_info["up_mod_days"].days
                else:
                    data["up_mod_days"] = None

                log.info("p0f: creating new log entry for %s@%s: uptime %s", browser.bid_public, remote_addr, data["uptime_sec"])
                BrowserP0f.objects.create(**data)

        except socket.error, e:
            sd.incr("p0f.error.socket", 1)
            log.error("p0f raised socket.error: %s", str(e))
