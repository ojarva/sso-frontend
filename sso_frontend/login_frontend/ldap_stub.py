""" LDAP authentication module """
import ldap
import logging
from django.conf import settings

__all__ = ["LdapLogin"]

log = logging.getLogger(__name__)

class LdapLogin:
    """ LDAP authentication module """

    def __init__(self, username, password, redis_instance):
        self._redis = redis_instance
        self.username = self.map_username(username)
        self.password = password
        self._ldap = None
        self.user_dn = settings.LDAP_USER_BASE_DN % self.username
        if self._redis is None:
            raise Exception("No redis instance provided")
        self.authenticated = False

    def map_username(self, username):
        """ Maps user aliases to username """
        r_k = "email-to-username-%s" % username
        username_tmp = self._redis.get(r_k)
        if username_tmp is not None:
            return username_tmp
        return username

    @property
    def ldap(self):
        """ Opens LDAP connection or returns cached connection, if available """
        return None

    def login(self):
        """ Tries to login with provided user credentials """
        if self.username == "test" and self.password == "testpassword":
            self.authenticated = True
            return True
        if self.username == "test_valid" and self.password == "testpassword":
            self.authenticated = True
            return True

        if self.username == "test_valid2" and self.password == "testpassword":
            self.authenticated = True
            return True

        if self.username == "test_admin" and self.password == "testpassword":
            self.authenticated = True
            return True
            
        if self.username == "server_down":
            return "server_down"
        return "invalid_credentials"

    def get_auth_tokens(self):
        """ Gets user tokens for pubtkt """
        if not self.authenticated:
            self.login()
        if not self.authenticated:
            raise Exception("Unable to authenticate")
        return ["futu"]
