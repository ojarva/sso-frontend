from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone

from login_frontend.models import User
import slumber
import _slumber_auth
import redis


from login_frontend.config import Config


class Command(BaseCommand):
    args = ''
    help = 'Fetches all users'

    def handle(self, *args, **options):
        config = Config()

        api = slumber.API(config.get("fum-api-endpoint"), auth=_slumber_auth.TokenAuth(config.get("fum-api-token")))

        c = 1
        while True:
            data = api.users.get(page=c)
            for user in data["results"]:
                username = user.get("username")
                first_name = user.get("first_name")
                last_name = user.get("last_name")
                email = user.get("email", "")
                phone1 = user.get("phone1", "")
                phone2 = user.get("phone2")
                if username is None or email is None:
                    continue
                if first_name is None or last_name is None:
                    self.stderr.write("Missing first or last name: %s" % username)
                    continue

                (user, _) = DjangoUser.objects.get_or_create(username=username, defaults={"email": email, "is_staff": False, "is_active": True, "is_superuser": False, "last_login": timezone.now(), "date_joined": timezone.now()})
                user.email = email
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                (obj, _) = User.objects.get_or_create(username=username)
                obj.refresh_strong(email, phone1, phone2)
                self.stdout.write('Refreshed %s (%s, %s, %s)' % (username, email, phone1, phone2))
            if "next" not in data or data["next"] is None:
                break
            c += 1
        self.stdout.write('Successfully fetched all users')

