from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone
from django.conf import settings

from login_frontend.utils import refresh_user
from login_frontend.models import User
import slumber
import _slumber_auth
import redis
import hashlib
import statsd
import random


sd = statsd.StatsClient()
r = redis.Redis(db=3)


class Command(BaseCommand): # pragma: no cover
    args = ''
    help = 'Fetches all users'

    def handle(self, *args, **options):
        api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                user_hash = hashlib.sha512(str(user)).hexdigest()
                stored_hash = r.get("user-refresh-hash-%s" % user["username"])
                if stored_hash == user_hash:
                    sd.incr("login_frontend.management.refresh_users.no_changes")
                    continue
                r.setex("user-refresh-hash-%s" % user["username"], user_hash, 86400 + random.randint(0, 7200))
                sd.incr("login_frontend.management.refresh_users.refresh")
                status = refresh_user(user)
                if status:
                    sd.incr("login_frontend.management.refresh_users.updated")
                    self.stdout.write('Refreshed %s (%s, %s, %s)' % (user.get("username"), user.get("email"), user.get("phone1"), user.get("phone2")))
            if "next" not in data or data["next"] is None:
                break
            c += 1
        self.stdout.write('Successfully fetched all users')

