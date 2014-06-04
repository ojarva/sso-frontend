
import re
from Crypto.Cipher import AES


__all__ = ["InvalidOTPException", "BadOtpException", "ReplayedOtpException", "DelayedOtpException", "IncorrectOtpException", "YubikeyValidate"]

class InvalidOTPException(Exception):
    """ Exception raised when OTP does not match """
    pass

class BadOtpException(InvalidOTPException):
    """ Format of the OTP does not match """
    pass

class ReplayedOtpException(InvalidOTPException):
    """ OTP reuse was detected """
    pass

class DelayedOtpException(InvalidOTPException):
    """ OTP was delayed too much """
    pass

class IncorrectOtpException(InvalidOTPException):
    """ Incorrect OTP - for example, unexpected userid """
    pass

class YubikeyValidate(object):
    """ This class validates Yubikey OTPs. """

    def __init__(self, otp = None):
        self.otp = otp

        if (len(self.otp) <= 32) or (len(self.otp) > 48):
            raise BadOtpException
        match = re.search('^([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})$', re.escape(self.otp))
        if match == None:
            raise BadOtpException
        self.match = match
        self.public_uid = self.match.group(1)

    @classmethod
    def hex2dec(cls, hex_val):
        """ Converts hexadecimal number to base10 """
        return int(hex_val, 16)

    @classmethod
    def modhex2hex(cls, string):
        """ Converts Yubikey hex to normal hexadecimal number. """
        charmap = {'c': '0', 'b': '1', 'e': '3', 'd': '2', 'g': '5', 'f': '4', 'i': '7', 'h': '6', 'k': '9', 'j': '8', 'l': 'a', 'n': 'b', 'r': 'c', 'u': 'e', 't': 'd', 'v': 'f'}
        ret = ''
        for char in string:
            mapped = charmap.get(char)
            if mapped is None:
                raise ValueError("Invalid Yubikey string")
            ret += mapped
        return ret

    @classmethod
    def calculate_crc(cls, plaintext):
        """ Calculates crc16 """
        crc = 0xffff
        for i in range(0, 16):
            decval = cls.hex2dec(plaintext[i*2] + plaintext[(i*2)+1])
            crc = crc ^ (decval & 0xff)
            for _ in range(0, 8):
                current_crc = crc & 1
                crc = crc >> 1
                if current_crc != 0:
                    crc = crc ^ 0x8408

        return crc == 0xf0b8

    @classmethod
    def aes128ecb_decrypt(cls, aeskey, aesdata):
        """ Decrypts AES128 string in ECB mode. """
        return AES.new(aeskey.decode('hex'), AES.MODE_ECB).decrypt(aesdata.decode('hex')).encode('hex')

    def validate(self, expected_public_uid, expected_private_uid, aeskey, last_counter, last_timestamp):
        """ Validates OTP value. Raises exception if code is not valid. """

        try:
            if self.public_uid != expected_public_uid:
                raise IncorrectOtpException
            token = self.modhex2hex(self.match.group(2))
            plaintext = self.aes128ecb_decrypt(aeskey, token)
            uid = plaintext[:12]
            if expected_private_uid != uid:
                raise IncorrectOtpException
            if not self.calculate_crc(plaintext):
                raise BadOtpException
            internalcounter = self.hex2dec(plaintext[14:16] + plaintext[12:14] + plaintext[22:24])
            timestamp = self.hex2dec(plaintext[20:22] + plaintext[18:20] + plaintext[16:18])
            if last_counter >= internalcounter:
                raise ReplayedOtpException
            if (last_timestamp >= timestamp) and ((last_counter >> 8) == (internalcounter >> 8)):
                raise DelayedOtpException
        except IndexError:
            raise BadOtpException
        return (internalcounter, timestamp)
