from django_statsd.clients import statsd as sd

def get_client_ip(request):
    """ From http://stackoverflow.com/a/5976065 """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class RealRemoteIP(object):
    @sd.timer("RealRemoteIP.process_request")
    def process_request(self, request):
        request.remote_ip = get_client_ip(request)

    @sd.timer("RealRemoteIP.process_response")
    def process_response(self, request, response):
        # This adds request.remote_ip for other process_response middlewares.
        request.remote_ip = get_client_ip(request)
        return response
