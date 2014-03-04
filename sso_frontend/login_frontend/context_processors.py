"""
Context processors for adding objects to templates.

These overwrite
- user
- browser
- username
- emulate_legacy
- first_name
- last_name
"""

from django.contrib.auth.models import User as DjangoUser
from login_frontend.models import Browser
import statsd

sd = statsd.StatsClient()


__all__ = ["add_static_timestamp", "add_browser", "add_user", "session_info"]

@sd.timer("login_frontend.context_processors.add_static_timestamp")
def add_static_timestamp(request):
    """ Adds unique number used for static files. """
    #TODO: determine automatically
    return {"static_timestamp": 1}

@sd.timer("login_frontend.context_processors.add_browser")
def add_browser(request):
    """ Adds "browser" to context, if available. """
    try:
        if request.browser:
            return {"browser": request.browser}
    except AttributeError:
        pass
    return {}

@sd.timer("login_frontend.context_processors.add_user")
def add_user(request):
    """ Adds user, username, emulate_legacy, first_name and last_name to context, if user is signed in. """
    try:
        if request.browser and request.browser.user:
            user = request.browser.user
            ret_dict = {"user": user, "username": user.username, "emulate_legacy": user.emulate_legacy}
            try:
                django_user = DjangoUser.objects.get(username=user.username)
                ret_dict["first_name"] = django_user.first_name
                ret_dict["last_name"] = django_user.last_name
            except DjangoUser.DoesNotExist:
                pass
            return ret_dict
    except AttributeError:
        pass
    return {}

@sd.timer("login_frontend.context_processors.session_info")
def session_info(request):
    """ Adds number of open sessions to the context. """
    ret = {}
    try:
        if request.browser and request.browser.user:
            # TODO: filter out expired sessions
            ret["num_sessions"] = Browser.objects.filter(user=request.browser.user).count()
    except AttributeError:
        pass
    return ret
