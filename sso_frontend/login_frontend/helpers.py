import datetime
import dateutil.parser

def is_authenticated(request):
    if request.session.get("relogin_time"):
        return dateutil.parser.parse(request.session.get("relogin_time")) > datetime.datetime.now()
    return False
