from django.core.management.base import BaseCommand, CommandError
from django.core.cache import get_cache
dcache = get_cache("default")


class Command(BaseCommand): # pragma: no cover

    def handle(self, *args, **options):
        for ip in args:
            dcache.set("location-only-%s" % ip, True, 86400 * 60)
