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
    """ Fetches all users from the backend and updates local database """
    args = ''
    help = 'Fetches all users and updates contact details and names'

    def handle(self, *args, **options):
        """ user_hashes cache is used for caching hash of user dictionary.
        This is used to avoid hitting the database for each user. Hashes
        expire at random times between one and two days. This is by design,
        to avoid spikes on database access, and to periodically
        validate contents of the local database. """
        api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))
        cache = get_cache("user_hashes")

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                user_hash = hashlib.sha512(str(user)).hexdigest()
                cache_key = "user-refresh-hash-%s" % user["username"]
                stored_hash = cache.get(cache_key)
                if stored_hash == user_hash:
                    sd.incr("login_frontend.management.refresh_users.no_changes")
                    continue
                cache.set(cache_key, user_hash, random.randint(86400, 2*86400))
                sd.incr("login_frontend.management.refresh_users.refresh")
                status = refresh_user(user)
                if status:
                    sd.incr("login_frontend.management.refresh_users.updated")
                    self.stdout.write('Refreshed %s (%s, %s, %s)' % (user.get("username"), user.get("email"), user.get("phone1"), user.get("phone2")))
            if "next" not in data or data["next"] is None:
                break
            c += 1
        self.stdout.write('Successfully fetched all users')
