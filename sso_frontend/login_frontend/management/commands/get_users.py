from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone
from django.conf import settings
from login_frontend.models import User

from django_statsd.clients import statsd as sd

# This is deprecated in 1.7.
from django.core.cache import get_cache

class Command(BaseCommand): # pragma: no cover
    args = ''
    help = 'Fetches users based on criteria'

    def handle(self, *args, **options):
        print args
        user = User.objects.all()
        for arg in args:
            k, v = arg.split("=")
            if v == "True": v = True
            if v == "False": v = False

            user = user.filter(**{k: v})
        for item in user:
            self.stdout.write(item.username)
