from django.core.management.base import BaseCommand, CommandError
from login_frontend.models import Yubikey
import csv

class Command(BaseCommand):
    args = '<file1.csv file2.csv ...>'
    help = 'Imports Yubikey values from CSV file'

    def handle(self, *args, **options):
        for csv_file in args:
            with open(csv_file, 'rb') as csvfile:
                keyreader = csv.reader(csvfile, delimiter=",")
                for line in keyreader:
                    if line[0] != "Yubico OTP":
                        continue
                    public_uid = line[3]
                    internal_uid = line[4]
                    secret = line[5]
                    yubikey, created = Yubikey.objects.get_or_create(public_uid=public_uid, internal_uid=internal_uid, secret=secret)
                    if created:
                        self.stdout.write('Successfully created Yubikey with public ID %s' % public_uid)
                    else:
                        self.stdout.write('Yubikey with public ID %s already exists' % public_uid)
