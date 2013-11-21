import ldap

SERVER = "ldaps://ldapng1.futurice.com"
USER_BASE_DN="uid=%s,ou=People,dc=futurice,dc=com"
GROUP_BASE_DN="ou=Groups,dc=futurice,dc=com"
TOKEN_MAP = {"TeamIT": "it", "Futurice": "futu", "External": "ext", "Customers": "cust", "TeamRecruits": "hr"}

def auth_get_tokens(username, password):
    try:
        l = ldap.initialize(SERVER)
    except ldap.SERVER_DOWN, e:
        raise e
    except:
        raise Exception("Unknown error while connecting to LDAP server")

    if "@" in username:
        # TODO: mapping from email to username, including aliases
        username = username.split("@")[0]

    user_dn = USER_BASE_DN % username
    try:
        l.simple_bind_s(user_dn, password)
    except ldap.INVALID_CREDENTIALS, e:
        raise e
    except ldap.NO_SUCH_OBJECT, e:
        raise e
    except:
        raise Exception("Unknown error while authenticating")

    groups = l.search_s("ou=Groups,dc=futurice,dc=com", ldap.SCOPE_SUBTREE, "uniqueMember=%s" % user_dn, ["cn"])

    tokens = []
    for (_, attrs) in groups:
        if "cn" not in attrs:
            continue
        if attrs["cn"][0] in TOKEN_MAP:
            tokens.append(TOKEN_MAP[attrs["cn"][0]])

    return tokens



