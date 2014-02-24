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
        if self._ldap is None:
            try:
                self._ldap = ldap.initialize(settings.LDAP_SERVER)
                if settings.LDAP_IGNORE_SSL:
                    log.debug("Ignoring LDAP SSL certificate checks")
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            except ldap.SERVER_DOWN, e:
                raise e
            except:
                raise Exception("Unknown error while connecting to LDAP server")
        return self._ldap

    def login(self):
        """ Tries to login with provided user credentials """
        try:
            self.ldap.simple_bind_s(self.user_dn, self.password)
        except ldap.INVALID_CREDENTIALS, e:
            return "invalid_credentials"
        except ldap.NO_SUCH_OBJECT, e:
            return "invalid_credentials"
        except ldap.SERVER_DOWN, e:
            log.error("LDAP server is down: %s", e)
            return "server_down"
        except ValueError:
            return "Unknown error while authenticating. Please try again."
        self.authenticated = True
        return True

    def get_auth_tokens(self):
        """ Gets user tokens for pubtkt """
        if not self.authenticated:
            self.login()
        if not self.authenticated:
            raise Exception("Unable to authenticate")
        groups = self.ldap.search_s(settings.LDAP_GROUPS_BASE_DN, ldap.SCOPE_SUBTREE, "uniqueMember=%s" % self.user_dn, ["cn"])

        tokens = []
        for (_, attrs) in groups:
            if "cn" not in attrs:
                continue
            if attrs["cn"][0] in settings.TOKEN_MAP:
                tokens.append(settings.TOKEN_MAP[attrs["cn"][0]])
        return tokens

