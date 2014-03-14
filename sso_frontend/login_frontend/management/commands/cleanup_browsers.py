from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone

from login_frontend.utils import refresh_user
from login_frontend.models import *
import slumber
import _slumber_auth
import logging
import datetime

from django.conf import settings

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    args = ''
    help = 'Deletes browsers with no activity for 5 days'

    def handle(self, *args, **options):
        cleanup_older_than=timezone.now()-datetime.timedelta(days=5)
        browsers = Browser.objects.filter(user=None).filter(modified__lte=cleanup_older_than)
        for browser in browsers:
            if browser.has_any_activity():
                continue
            logger.info("Cleaning up inactive browser: %s" % browser.bid_public)
            self.stdout.write(str(browser))
            browser.delete()
