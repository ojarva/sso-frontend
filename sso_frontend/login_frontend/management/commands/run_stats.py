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

from django.conf import settings

logger = logging.getLogger(__name__)
sd = statsd.StatsClient()


class Command(BaseCommand):
    args = ''
    help = 'Exports various stats to graphite'

    def handle(self, *args, **options):
        # Total counts
        sd.gauge("stats.models.Browser.total", Browser.objects.all().count())
        sd.gauge("stats.models.User.total", User.objects.all().count())
        sd.gauge("stats.models.Log.total", Log.objects.all().count())
        sd.gauge("stats.models.Browser.total", Browser.objects.all().count())
        sd.gauge("stats.models.BrowserTime.total", BrowserTime.objects.all().count())
        sd.gauge("stats.models.BrowserP0f.total", BrowserP0f.objects.all().count())
        sd.gauge("stats.models.BrowserLogin.total", BrowserLogin.objects.all().count())
        sd.gauge("stats.models.BrowserUsers.total", BrowserUsers.objects.all().count())
        sd.gauge("stats.models.BrowserDetails.total", BrowserDetails.objects.all().count())
        sd.gauge("stats.models.KeystrokeSequence.total", KeystrokeSequence.objects.all().count())
        sd.gauge("stats.models.UserService.total", UserService.objects.all().count())
        sd.gauge("stats.models.AuthenticatorCode.total", AuthenticatorCode.objects.all().count())
        sd.gauge("stats.models.EmergencyCodes.total", EmergencyCodes.objects.all().count())
        sd.gauge("stats.models.EmergencyCodes.total_valid", EmergencyCodes.objects.exclude(downloaded_at=None).exclude(current_code=None).count())

        # Strong configuration
        sd.gauge("stats.models.User.strong_configured", User.objects.all().filter(strong_configured=True).count())
        sd.gauge("stats.models.User.strong_sms_always", User.objects.all().filter(strong_sms_always=True).count())
        sd.gauge("stats.models.User.emulate_legacy", User.objects.all().filter(emulate_legacy=True).count())
        sd.gauge("stats.models.User.strong_authenticator_secret", User.objects.all().exclude(strong_authenticator_secret=None).count())
        sd.gauge("stats.models.User.strong_authenticator_used", User.objects.filter(strong_authenticator_used=True).count())
        sd.gauge("stats.models.User.primary_phone_changed", User.objects.all().filter(primary_phone_changed=True).count())
        sd.gauge("stats.models.User.no_phone_available", User.objects.all().filter(primary_phone=None, secondary_phone=None).count())

        # Browsers
        sd.gauge("stats.models.Browser.associated_user", Browser.objects.all().exclude(user=None).count())

        # BrowserLogin
        sd.gauge("stats.models.BrowserLogin.active", BrowserLogin.objects.all().filter(signed_out=False, expires_at__gt=timezone.now()).count())


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
