from django.contrib.auth.models import User as DjangoUser

def add_browser(request):
    if request.browser:
        return {"browser": request.browser}
    return {}

def add_user(request):
    if request.browser and request.browser.user:
        user = request.browser.user
        ret_dict = {"user": user, "username": user.username}
        try:
            django_user = DjangoUser.objects.get(username=user.username)
            ret_dict["first_name"] = django_user.first_name
            ret_dict["last_name"] = django_user.last_name
        except DjangoUser.DoesNotExist:
            pass
        return ret_dict
    return {}
