from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User as DjangoUser
from django.utils import timezone
from django.conf import settings

from login_frontend.models import *
import json
from django.conf import settings
import datetime

class Command(BaseCommand): # pragma: no cover
    args = ''
    help = 'Imports keystroke timing logs to database'

    def handle(self, *args, **options):
        f = open(settings.PROJECT_ROOT+"logs/timing")
        for line in f:
           line = line.strip().split(" - {")
           line_start = line[0].split(" - ")

           timestamp = line_start[0]
           unix_time = timestamp.split("] ")[2]
           aware_timestamp = timezone.make_aware(datetime.datetime.fromtimestamp(int(float(unix_time))), None)
           timestamp = aware_timestamp

           username = line_start[1]
           ua = line_start[2]
           line_end = line[1].split("} - ")
           json_data = "{ %s }" % line_end[0]
           bid_public = line_end[1]
           data = json.loads(json_data)

           resolution = data.get("resolution")
           if isinstance(resolution, dict):
               resolution = "%s x %s" % (resolution.get("width"), resolution.get("height"))
           else:
               resolution = "None"
           remote_clock = data.get("browserclock")
           remote_clock_offset = remote_clock.get("timezoneoffset")
           remote_clock_time = remote_clock.get("utciso")

           plugins = data.get("plugins")

           performance = data.get("performance")
           performance_performance = performance_memory = performance_timing = performance_navigation = None
           if isinstance(performance, dict):
               performance_performance = performance.get("performance")
               performance_memory = performance.get("memory")
               performance_timing = performance.get("timing")
               performance_navigation = performance.get("navigation")


           try:
               browser = Browser.objects.get(bid_public=bid_public)
           except Browser.DoesNotExist:
               self.stderr.write("Browser %s does not exist" % bid_public)
               continue

           try:
               user = User.objects.get(username=username)
           except User.DoesNotExist:
               self.stderr.write("User %s does not exist" % username)
               continue

           BrowserDetails.objects.create(browser=browser, timestamp=timestamp, remote_clock_offset=str(remote_clock_offset), remote_clock_time=str(remote_clock_time), performance_performance=str(performance_performance), performance_memory=str(performance_memory), performance_timing=str(performance_timing), performance_navigation=str(performance_navigation), resolution=str(resolution), plugins=str(plugins))

           if "id_username" in data:
               fieldname = KeystrokeSequence.USERNAME
               timing = str(data.get("id_username"))
               KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timestamp, resolution=resolution, was_correct=True)

           if "id_password" in data:
               fieldname = KeystrokeSequence.PASSWORD
               timing = str(data.get("id_password"))
               KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timestamp, resolution=resolution, was_correct=True)

           if "id_otp" in data:
               fieldname = KeystrokeSequence.OTP_AUTHENTICATOR
               timing = str(data.get("id_otp"))
               KeystrokeSequence.objects.create(user=user, browser=browser, fieldname=fieldname, timing=timing, timestamp=timestamp, resolution=resolution, was_correct=True)

        self.stdout.write('Successfully imported all entries')
