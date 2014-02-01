from django.core.management.base import BaseCommand, CommandError
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
                email = user.get("email")
                phone1 = user.get("phone1")
                phone2 = user.get("phone2")
                if username is None or email is None or phone1 is None:
                    continue
                if min(len(email), len(phone1)) < 5:
                    continue
      
                (obj, _) = User.objects.get_or_create(username=username)
                obj.refresh_strong(email, phone1, phone2)
                self.stdout.write('Refreshed %s (%s, %s, %s)' % (username, email, phone1, phone2))
            if "next" not in data or data["next"] is None:
                break
            c += 1
        self.stdout.write('Successfully fetched all users')

