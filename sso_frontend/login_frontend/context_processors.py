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

from django.conf import settings
from django.contrib.auth.models import User as DjangoUser
from login_frontend.models import Browser
from django.utils.functional import SimpleLazyObject
from django_statsd.clients import statsd as sd
from django.core.cache import get_cache

dcache = get_cache("default")

__all__ = ["add_misc_info", "add_user", "add_session_info"]

def add_misc_info(request):
    ret = {}
    ret["admin_email"] = settings.ADMIN_CONTACT_EMAIL
    if hasattr(request, "vulnerability"):
        ret["vulnerability"] = request.vulnerability
    if hasattr(request, "ask_location"):
        ret["ask_location"] = request.ask_location
    if hasattr(request, "browser") and request.browser:
        browser = request.browser
        ret["auth_status"] = browser.get_auth_state()
        ret["browser"] = browser
    return ret

@sd.timer("login_frontend.context_processors.add_user")
def add_user(request):
    """ Adds user, username, emulate_legacy, first_name and last_name to context, if user is signed in. """
    try:
        if request.browser and request.browser.user:
            user = request.browser.user
            ret_dict = {"user": user, "username": user.username, "emulate_legacy": user.emulate_legacy}
            ret_dict["first_name"] = dcache.get("first_name-for-%s" % user.username)
            ret_dict["last_name"] = dcache.get("last_name-for-%s" % user.username)
            if ret_dict["first_name"] is None or ret_dict["last_name"] is None:
                try:
                    django_user = DjangoUser.objects.get(username=user.username)
                    ret_dict["first_name"] = django_user.first_name
                    ret_dict["last_name"] = django_user.last_name
                    dcache.set("first_name-for-%s" % user.username, django_user.first_name, 7200)
                    dcache.set("last_name-for-%s" % user.username, django_user.last_name, 7200)
                except DjangoUser.DoesNotExist:
                    pass
            return ret_dict
    except AttributeError:
        pass
    return {}

@sd.timer("login_frontend.context_processors.session_info")
def add_session_info(request):
    """ Adds number of open sessions to the context. """
    if not (hasattr(request, "browser") and request.browser and request.browser.user):
        return {}

    r_k = "num_sessions-%s" % request.browser.user.username
    num_sessions = dcache.get(r_k)

    def get_num_sessions():
        try:
            if request.browser and request.browser.user:
                # TODO: filter out expired sessions
                val = Browser.objects.filter(user=request.browser.user).count()
                dcache.set(r_k, val, 1800)
                return val
        except AttributeError:
            return None

    if not num_sessions:
        num_sessions = SimpleLazyObject(get_num_sessions)
    ret = {}
    ret["num_sessions"] = num_sessions
    return ret
