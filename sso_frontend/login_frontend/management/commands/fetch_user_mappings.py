from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone
from django.conf import settings

from login_frontend.utils import refresh_user
from login_frontend.models import User
import slumber
import _slumber_auth
import hashlib
from django_statsd.clients import statsd as sd
import random

# This is deprecated in 1.7.
from django.core.cache import get_cache

class Command(BaseCommand): # pragma: no cover
    args = ''
    help = 'Fetches user email mappings'
    KEY_EXPIRE = 60 * 60 * 24 * 30 # 30 days

    def handle(self, *args, **options):
        api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))
        cache = get_cache("user_mapping")

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                if not "username" in user:
                    continue
                cache.set("email-to-username-%s@futu" % user["username"], user["username"], self.KEY_EXPIRE)
                if "email" in user:
                    cache.set("email-to-username-%s" % user["email"], user["username"], self.KEY_EXPIRE)
                    cache.set("username-to-email-%s" % user["username"], user["email"], self.KEY_EXPIRE)
                for email in user.get("email_aliases", []):
                    cache.set("email-to-username-%s" % email, user["username"], self.KEY_EXPIRE)
            c += 1
            if "next" not in data or data["next"] is None:
                break
