from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone
from django.db.models import Count


from login_frontend.utils import refresh_user
from login_frontend.models import *
import slumber
import _slumber_auth
import logging
import datetime
import statsd
from random import randint
from django.core.cache import get_cache


from django.conf import settings

logger = logging.getLogger(__name__)
sd = statsd.StatsClient()
dcache = get_cache("default")


__all__ = ["Command"]

STATS = (
    ("stats.models.Browser.total", "Browser.objects.all().count()"),
    ("stats.models.User.total", "User.objects.all().count()"),
    ("stats.models.Log.total", "Log.objects.all().count()"),
    ("stats.models.BrowserTime.total", "BrowserTime.objects.all().count()"),
    ("stats.models.BrowserP0f.total", "BrowserP0f.objects.all().count()"),
    ("stats.models.BrowserLogin.total", "BrowserLogin.objects.all().count()"),
    ("stats.models.BrowserUsers.total", "BrowserUsers.objects.all().count()"),
    ("stats.models.BrowserDetails.total", "BrowserDetails.objects.all().count()"),
    ("stats.models.KeystrokeSequence.total", "KeystrokeSequence.objects.all().count()"),
    ("stats.models.UserService.total", "UserService.objects.all().count()"),
    ("stats.models.AuthenticatorCode.total", "AuthenticatorCode.objects.all().count()"),
    ("stats.models.EmergencyCodes.total", "EmergencyCodes.objects.all().count()"),
    ("stats.models.EmergencyCodes.total_valid", "EmergencyCodes.objects.exclude(downloaded_at=None).exclude(current_code=None).count()"),

    # Strong configuration
    ("stats.models.User.strong_configured", "User.objects.all().filter(strong_configured=True).count()"),
    ("stats.models.User.strong_sms_always", "User.objects.all().filter(strong_sms_always=True).count()"),
    ("stats.models.User.emulate_legacy", "User.objects.all().filter(emulate_legacy=True).count()"),
    ("stats.models.User.strong_authenticator_secret", "User.objects.all().exclude(strong_authenticator_secret=None).count()"),
    ("stats.models.User.strong_authenticator_used", "User.objects.filter(strong_authenticator_used=True).count()"),
    ("stats.models.User.primary_phone_changed", "User.objects.all().filter(primary_phone_changed=True).count()"),
    ("stats.models.User.no_phone_available", "User.objects.all().filter(primary_phone=None, secondary_phone=None).count()"),

    # Browsers
    ("stats.models.Browser.associated_user", "Browser.objects.all().exclude(user=None).count()"),

    # BrowserLogin
    ("stats.models.BrowserLogin.active", "BrowserLogin.objects.all().filter(signed_out=False, expires_at__gt=_now_).count()"),
)

def run_stat(statkey, stat_query):
    now = timezone.now()

    val = dcache.get("runstats-%s" % statkey)
    if val != None:
        # Cached value exists. Use that and exit.
        sd.gauge(statkey, val)
        return
    stat_query = stat_query.split(".")
    obj = globals().get(stat_query[0]) # Get model class
    for query_func in stat_query[1:]:
        if "(" not in query_func:
            # Object, not function
            obj = getattr(obj, query_func)
        else:
            # Function
            (func, params) = query_func.split("(")
            # Get function from parent object
            o = getattr(obj, func)
            # Remove trailing ")" from parameters
            params = params.replace(")", "").strip()
            if len(params) > 0:
                # Includes query parameters
                params = params.split(",")
            else:
                params = []
            p = {}
            for param in params:
                (param_key, param_value) = param.split("=")
                if param_value == "_now_":
                    param_value = now
                elif param_value == "None":
                    param_value = None
                p[param_key.strip()] = param_value
            # Call function with kwargs ** magic
            obj = o(**p)
    val = obj
    sd.gauge(statkey, val)
    # Set cache value. Randomize expire to avoid simultaneous hits.
    dcache.set("runstats-%s" % statkey, val, 3600 + randint(0, 3600))

class Command(BaseCommand):
    args = ''
    help = 'Exports various stats to graphite'

    def handle(self, *args, **options):
        for (statkey, stat_query) in STATS:
            run_stat(statkey, stat_query)

        # Browsers: authentication states
        auth_states = Browser.objects.values("auth_state").annotate(Count("auth_state"))
        for (i, name) in ((0, "request_basic"), (1, "request_strong"), (2, "request_basic_only"), (3, "authenticated")):
            count = 0
            for auth_state in auth_states:
                if auth_state["auth_state"] == i:
                    count = auth_state["auth_state__count"]
                    break
            sd.gauge("stats.models.Browser.auth_state.%s" % name, count)

        # Browsers: authentication level
        auth_levels = Browser.objects.values("auth_level").annotate(Count("auth_level"))
        for (i, name) in ((0, "unauth"), (1, "public"), (2, "basic"), (3, "strong"), (4, "strong_skipped")):
            count = 0
            for auth_level in auth_levels:
                if auth_level["auth_level"] == i:
                    count = auth_level["auth_level__count"]
                    break
            sd.gauge("stats.models.Browser.auth_level.%s" % name, count)
