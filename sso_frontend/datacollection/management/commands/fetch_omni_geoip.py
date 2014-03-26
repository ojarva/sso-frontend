from datacollection.maxmind import get_omni_data
from django.core.management.base import BaseCommand, CommandError

class Command(BaseCommand): # pragma: no cover

    def handle(self, *args, **options):
        for ip in args:
            self.stdout.write("Fetching information for %s" % ip)
            self.stdout.write("%s" % get_omni_data(ip))
