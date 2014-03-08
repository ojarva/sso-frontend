import urlparse

GOOGLE_SAML_SERVICE = {
 "CPanel": "Admin panel",
 "cl": "Calendar",
 "mail": "gmail",
 "wise": "Drive",
 "writely": "Drive",
 "lso": "OAuth",
 "groups2": "Groups",
 "analytics": "Analytics",
 "oz": "Plus",
 "talk": "Hangouts",
 "local": "Maps",
 "youtube": "Youtube",
}

def parse_google_saml(relay_state):
    """ Parses Google SAML RelayState URLs to human readable format.
    'https://www.google.com/a/futurice.com/ServiceLogin?service=mail&passive=true&rm=false&continue=https%3A%2F%2Fmail.google.com%2Fa%2Ffuturice.com%2F&ss=1&ltmpl=default&ltmplcache=2&emr=1'
     |     parsed.hostname                             | parsed.query                                                                                                                        |
                                                                                                    | parsed_continue                                |

    Notes:
     - parsed.query["service"] is not always available. If it is,
        * CPanel: admin panel
        * cl: calendar
        * mail: gmail
        * wise: Drive (?)
        * writely: Drive (?)
        * lso: OAuth?
        * groups2: Groups
        * analytics: Analytics
        * oz: plus.google.com
        * talk: Hangouts
        * local: Maps
        * youtube: Youtube
     - Different services redirect to different hosts (parsed_continue.hostname)
        * mail: mail.futurice.com (but not always)
        * Drive: docs.google.com (redirected to drive.futurice.com) or drive.futurice.com
        * Groups: groups.google.com
        * Plus: plus.google.com
        * Chrome/Android Sync: www.google.com
     - Some services have per-country domains: for example, maps.google.com.au
     - In some cases, parsed_continue.hostname is accounts.google.com, which is then redirected to destination service.
     - In some cases, parsed.hostname is accounts.google.com
     - Parameters in parsed.query:
        * btmpl: authsub/mobile
        * hl: language. Not always present.
        * followup: Google first redirects user to continue, and after that to followup. Usually within the same service.
        No idea what these do:
        * skipvpage: True when signing in to admin panel.
        * rm, emr: 1 or non-existing.
        * ss: 1 or non-existing.
        * sarp: 1 or non-existing.
        * shdf: internal hash, no idea what it contains
    """
    # Parse relay_state
    parsed = urlparse.urlparse(relay_state)
    # Parse query parameters to dictionary
    query = urlparse.parse_qs(parsed.query)

    if "continue" in query:
        # Parse URL found from "continue" query parameter
        parsed_continue = urlparse.urlparse(query["continue"][0])
        # Parse query parameters from continue URL
        query_continue = urlparse.parse_qs(parsed_continue.query)
        return_url = None
        if 'xoauth_display_name' in query_continue:
            # Human readable OAuth name, e.g "Android Sync Service". Basically, the text user sees in OAuth authorization view.
            return_url = query_continue['xoauth_display_name'][0]
        elif parsed_continue.path.startswith('/o/oauth'):
            # No human readable OAuth name available (or different version of OAuth)
            return_url = "Google OAuth"
            if "redirect_uri" in query_continue:
                parsed_redirect_uri = urlparse.urlparse(query_continue["redirect_uri"][0])
                if parsed_redirect_uri.hostname:
                    return_url = "Google OAuth to %s" % parsed_redirect_uri.hostname
            if "origin" in query_continue:
                parsed_origin = urlparse.urlparse(query_continue["origin"][0])
                if parsed_origin.hostname:
                    return_url = "Google OAuth to %s" % parsed_origin.hostname
        elif parsed_continue.path.startswith('/o/oauth2/'):
            return_url = "Google OAuth2"
            if "device_name" in query_continue:
                return_url = "Google OAuth2 (%s)" % query_continue["device_name"][0]
        elif "service" in query and query["service"][0] == "chromiumsync":
            # Special case: 
            return_url = "Chrome Sync"
        elif query["continue"][0].startswith("https://accounts.google.com/o/openid2"):
            return_url = "Google OpenID"
        elif parsed_continue.hostname == "www.google.com" and parsed_continue.path.startswith("/calendar/"):
            return_url = "Google Calendar"
        elif parsed_continue.hostname:
            host = parsed_continue.hostname
            if host == "mail.google.com":
                return_url = "gmail"
            elif host == "docs.google.com" or host == "drive.google.com":
                return_url = "Drive"   
            elif host == "groups.google.com":
                return_url = "Google Groups"
            elif host == "plus.google.com":
                return_url = "Google Plus"
        if not return_url:
            # no match from URLs, try with services
            if "service" in query:
                return_url = GOOGLE_SAML_SERVICE.get(query["service"][0])
        return return_url


def get_destination_service(url):
    return_url = url
    try:
        parsed = urlparse.urlparse(url)
        if parsed.hostname == "www.google.com":
            # Example ACS url: https://www.google.com/a/futurice.com/acs
            b = parsed.path.split("/")
            if len(b) > 2:
                return "%s (%s)" % (parsed.hostname, b[2])
    except:
        pass
    return return_url
