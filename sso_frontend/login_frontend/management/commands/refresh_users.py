from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone

from login_frontend.utils import refresh_user
from login_frontend.models import User
import slumber
import _slumber_auth
import redis

from django.conf import settings


class Command(BaseCommand):
    args = ''
    help = 'Fetches all users'

    def handle(self, *args, **options):
        api = slumber.API(settings.FUM_API_ENDPOINT, auth=_slumber_auth.TokenAuth(settings.FUM_ACCESS_TOKEN))

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                status = refresh_user(user)
                if status:
                    self.stdout.write('Refreshed %s (%s, %s, %s)' % (username, email, phone1, phone2))
            if "next" not in data or data["next"] is None:
                break
            c += 1
        self.stdout.write('Successfully fetched all users')

