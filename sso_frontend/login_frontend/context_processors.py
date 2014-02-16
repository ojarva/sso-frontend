from django.contrib.auth.models import User as DjangoUser
from models import Browser

def add_browser(request):
    if request.browser:
        return {"browser": request.browser}
    return {}

def add_user(request):
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
    return {}

def session_info(request):
    ret = {}
    if request.browser and request.browser.user:
        # TODO: filter out expired sessions
        ret["num_sessions"] = Browser.objects.filter(user=request.browser.user).count()
    return ret
