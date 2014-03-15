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
        user_cache = get_cache("users")

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                if not "username" in user:
                    continue
                username = user["username"]
                email = user["email"]
                user_aliases = ["%s@futu" % username, email]
                cache.set("email-to-username-%s@futu" % username, username, self.KEY_EXPIRE)
                if "email" in user:
                    cache.set("email-to-username-%s" % email, username, self.KEY_EXPIRE)
                    cache.set("username-to-email-%s" % username, email, self.KEY_EXPIRE)
                for email_alias in user.get("email_aliases", []):
                    cache.set("email-to-username-%s" % email_alias, username, self.KEY_EXPIRE)
                    user_aliases.append(email_alias)
                user_cache.set("%s-aliases" % username, user_aliases, self.KEY_EXPIRE)
            c += 1
            if "next" not in data or data["next"] is None:
                break
