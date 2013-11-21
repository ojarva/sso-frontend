from urlparse import urlparse
import datetime
import dateutil.parser

class BackUrlValidator:
    def __init__(self, back_url, valid_domains):
        self.parsed_url = urlparse(back_url)
        self.invalid = False 
        self.hostname = self.parsed_url.hostname
        if self.parsed_url.scheme is not "https":
            self.invalid_scheme = True
            self.invalid = True

        if self.parsed_url.hostname:
            for domain in valid_domains:
                if self.parsed_url.hostname.endswith(domain):
                    break
            else:
                self.server_not_allowed = True
                self.invalid = True
        else:
            self.server_not_allowed = True
            self.invalid = True
            self.hostname = "-"

        self.url = back_url


def is_authenticated(request):
    if request.session.get("relogin_time"):
        return dateutil.parser.parse(request.session.get("relogin_time")) > datetime.datetime.now()
    return False
