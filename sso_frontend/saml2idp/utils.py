from urlparse import urlparse

def get_destination_service(url):
    return_url = url
    try:
        parsed = urlparse(url)
        if parsed.hostname == "www.google.com":
            # Example ACS url: https://www.google.com/a/futurice.com/acs
            b = parsed.path.split("/")
            if len(b) > 2:
                return "%s (%s)" % (parsed.hostname, b[2])
    except:
        pass
    return return_url
