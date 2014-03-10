"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from login_frontend.models import User, AuthenticatorCode
import pyotp
import time

def get_code(totp, timestamp):
    return ("000000"+str(totp.at(timestamp)))[-6:]


class OTPTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='testuser')

    def test_old_authenticators_saved(self):
        first_authenticator = self.user.gen_authenticator()
        self.assertEqual(AuthenticatorCode.objects.all().count(), 1)
        second_authenticator = self.user.gen_authenticator()
        self.assertEqual(AuthenticatorCode.objects.all().count(), 2)
        authenticator_secrets = [a["authenticator_secret"] for a in AuthenticatorCode.objects.all().values("authenticator_secret")]
        self.assertTrue(first_authenticator in authenticator_secrets)
        self.assertTrue(second_authenticator in authenticator_secrets)

    def test_ids(self):
        first_authenticator = self.user.gen_authenticator()
        self.assertEqual(AuthenticatorCode.objects.all().count(), 1)
        self.assertEqual(self.user.strong_authenticator_num, 1)
        second_authenticator = self.user.gen_authenticator()
        self.assertEqual(AuthenticatorCode.objects.all().count(), 2)
        self.assertEqual(self.user.strong_authenticator_num, 2)

    def test_history_contents(self):        
        first_authenticator = self.user.gen_authenticator()
        self.assertEqual(AuthenticatorCode.objects.all().count(), 1)
        first_authenticator_history = AuthenticatorCode.objects.get(authenticator_secret=first_authenticator)
        self.assertEqual(first_authenticator_history.generated_at, self.user.strong_authenticator_generated_at)
        self.assertEqual(first_authenticator_history.authenticator_id, self.user.strong_authenticator_id)
        self.assertEqual(first_authenticator_history.user, self.user)

        second_authenticator = self.user.gen_authenticator()
        self.assertNotEqual(first_authenticator, second_authenticator)
        self.assertEqual(AuthenticatorCode.objects.all().count(), 2)
        second_authenticator_history = AuthenticatorCode.objects.get(authenticator_secret=second_authenticator)
        
        self.assertEqual(first_authenticator_history.authenticator_secret, first_authenticator)
        self.assertEqual(first_authenticator_history.user, self.user)
        self.assertNotEqual(first_authenticator_history.authenticator_id, self.user.strong_authenticator_id)

        self.assertEqual(second_authenticator_history.generated_at, self.user.strong_authenticator_generated_at)
        self.assertEqual(second_authenticator_history.authenticator_id, self.user.strong_authenticator_id)
        self.assertEqual(second_authenticator_history.user, self.user)


    def test_current_code(self):
        first_authenticator = self.user.gen_authenticator()
        totp = pyotp.TOTP(first_authenticator)
        code = get_code(totp, time.time())
        (status, message) = self.user.validate_authenticator_code(code, None)
        self.assertTrue(status, "Code with current timestamp was not accepted")
        self.assertEqual(message, None, "Validation returned message")

    def test_next_prev_codes(self):
        first_authenticator = self.user.gen_authenticator()
        totp = pyotp.TOTP(first_authenticator)
        a = time.time() - 20
        (status, message) = self.user.validate_authenticator_code(get_code(totp, a), None)
        self.assertTrue(status, "Code at -20s was not accepted: %s" % message)
        self.assertEqual(message, None, "Validation returned message: %s" % message)

        a = time.time() + 20
        (status, message) = self.user.validate_authenticator_code(get_code(totp, a), None)
        self.assertTrue(status, "Code at +20s was not accepted: %s" % message)
        self.assertEqual(message, None, "Validation returned message: %s" % message)

    def test_authenticator_not_configured(self):
        (status, message) = self.user.validate_authenticator_code("000000", None)
        self.assertFalse(status, "Invalid code accepted.")
        self.assertEqual(message, "Authenticator is not configured")

    def test_invalid_codes(self):
        first_authenticator = self.user.gen_authenticator()
        totp = pyotp.TOTP(first_authenticator)
        a = time.time() - 20
        (status, message) = self.user.validate_authenticator_code("000000", None) # Yes, this might fail, but not too often.
        self.assertFalse(status, "Invalid code was accepted")
        self.assertEqual(message, "Incorrect OTP code.", "Invalid message returned: %s" % message)

        (status, message) = self.user.validate_authenticator_code("", None)
        self.assertFalse(status, "Invalid code was accepted")
        self.assertEqual(message, "Incorrect OTP code.", "Invalid message returned: %s" % message)

        (status, message) = self.user.validate_authenticator_code("adsf", None)
        self.assertFalse(status, "Invalid code was accepted")
        self.assertEqual(message, "Incorrect OTP code.", "Invalid message returned: %s" % message)

    def test_same_code_multiple_times(self):
        first_authenticator = self.user.gen_authenticator()
        totp = pyotp.TOTP(first_authenticator)
        code = get_code(totp, time.time())

        (status, message) = self.user.validate_authenticator_code(code, None)
        self.assertTrue(status, "Valid code was not accepted: %s" % message)
        self.assertEqual(message, None, "Validation returned message: %s" % message)

        (status, message) = self.user.validate_authenticator_code(code, None)
        self.assertFalse(status, "Duplicate code was accepted")
        self.assertEqual(message, "OTP was already used. Please wait for 30 seconds and try again.", "Invalid message for duplicate code: %s" % message)

    def test_detect_old_authenticator(self):
        first_authenticator = self.user.gen_authenticator()
        authenticator_name = self.user.strong_authenticator_id
        generated_at = self.user.strong_authenticator_generated_at
        totp1 = pyotp.TOTP(first_authenticator)
        second_authenticator = self.user.gen_authenticator()
        totp2 = pyotp.TOTP(second_authenticator)

        (status, message) = self.user.validate_authenticator_code(get_code(totp1, time.time()), None)
        self.assertFalse(status, "Old code was accepted")
        self.assertEqual(message, "You tried to use old Authenticator configuration, generated at %s. If you don't have newer configuration, please sign in with SMS and reconfigure Authenticator." % generated_at)

        (status, message) = self.user.validate_authenticator_code(get_code(totp1, time.time() - 90), None)
        self.assertFalse(status, "Old code was accepted")
        time_diff = "-90"
        self.assertEqual(message, "You tried to use old Authenticator configuration, generated at %s. If you don't have newer configuration, please sign in with SMS and reconfigure Authenticator. Also, clock of your mobile phone seems to be off by about %s seconds" % (generated_at, time_diff))

    def test_detect_old_code(self):
        first_authenticator = self.user.gen_authenticator()
        totp1 = pyotp.TOTP(first_authenticator)

        (status, message) = self.user.validate_authenticator_code(get_code(totp1, time.time()-120), None)
        self.assertFalse(status, "Old code was accepted")
        self.assertEqual(message, 'Incorrect code. It seems your clock is off by about -120 seconds, or you waited too long before entering the code.')

        (status, message) = self.user.validate_authenticator_code(get_code(totp1, time.time()+120), None)
        self.assertFalse(status, "Old code was accepted")
        self.assertEqual(message, 'Incorrect code. It seems your clock is off by about 120 seconds.')
