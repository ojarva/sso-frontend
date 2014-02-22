#pylint: disable-msg=C0301
""" Admin frontend views for login.

This is not integrated to Django admin.
"""

from django.contrib import messages
from django.contrib.auth.models import User as DjangoUser
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from login_frontend.models import Browser, User, BrowserLogin, BrowserUsers, Log
from login_frontend.utils import get_and_refresh_user
from login_frontend.views import protect_view
import logging
import redis


log = logging.getLogger(__name__)
r = redis.Redis()

user_log = logging.getLogger(__name__)
def custom_log(request, message, **kwargs):
    """ Automatically adds remote IP address and public browser ID to log entries """
    level = kwargs.get("level", "info")
    method = getattr(user_log, level)
    remote_addr = request.META.get("REMOTE_ADDR")
    bid_public = username = ""
    if request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("%s - %s - %s - %s", remote_addr, username, bid_public, message)

@require_http_methods(["GET"])
@protect_view("indexview", required_level=Browser.L_STRONG, admin_only=True)
def indexview(request, **kwargs):
    """ Main page. If keyword argument body_only is set, returns only main content, excluding menus. """
    custom_log(request, "Admin: frontpage")
    ret = {}
    ret["users"] = User.objects.all().count()
    ret["browsers"] = Browser.objects.all().count()
    ret["active_logins"] = BrowserLogin.objects.filter(signed_out=False).filter(expires_at__gte=timezone.now()).count()

    ret["num_strong_configured"] = User.objects.filter(strong_configured=True).count()
    ret["num_sms_always"] = User.objects.filter(strong_sms_always=True).count()
    ret["num_authenticator_used"] = User.objects.filter(strong_authenticator_used=True).count()
    ret["num_strong_configured_not_used"] = User.objects.exclude(strong_authenticator_generated_at=None).filter(strong_authenticator_used=False).count()
    ret["num_skips"] = User.objects.filter(strong_skips_available__gt=0).filter(strong_skips_available__lt=6).filter(strong_configured=False).count()

    active_browsers = Browser.objects.exclude(user=None)
    ret["active_browsers"] = []
    for browser in active_browsers:
        if browser.auth_level_valid_until > timezone.now() and browser.auth_state_valid_until > timezone.now() and browser.auth_level >= Browser.L_STRONG:
            ret["active_browsers"].append(browser)

    ret["last_logins"] = BrowserLogin.objects.all()[0:10]

    ret["admins"] = User.objects.filter(is_admin=True)

    if kwargs.get("body_only"):
        return render_to_response("admin_frontend/snippets/indexview.html", ret, context_instance=RequestContext(request))
     
    return render_to_response("admin_frontend/indexview.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("users", required_level=Browser.L_STRONG, admin_only=True)
def users(request):
    """ Returns list of users.
    TODO: pagination
    """
    custom_log(request, "Admin: users")
    ret = {}
    ret["users"] = User.objects.all().order_by('username')
    return render_to_response("admin_frontend/users.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("search", required_level=Browser.L_STRONG, admin_only=True)
def search(request):
    """ Search view. Shows

    - active browsers for user (if keyword is username)
    - all browsers where either public browser ID or user agent (wildcard) matches.
    - All browsers user have ever used, if keyword is username
    - All users with matching username, email, primary or secondary phone
    """

    q = request.GET.get("q")
    ret = {}
    ret["q"] = q
    ret["browsers"] = Browser.objects.filter(Q(bid_public=q) | Q(ua__icontains=q))[0:100]
    ret["active_browsers_for_user"] = Browser.objects.filter(user__username=q)
    ret["all_browsers_for_user"] = BrowserUsers.objects.filter(user__username=q)
    ret["users"] = User.objects.filter(Q(username=q) | Q(email=q) | Q(primary_phone__contains=q) | Q(secondary_phone__contains=q))[0:100]

    return render_to_response("admin_frontend/search.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET", "POST"])
@protect_view("userdetails", required_level=Browser.L_STRONG, admin_only=True)
def userdetails(request, **kwargs):
    """ Shows details for a single user. Allows refreshing (from LDAP),
        signing out sessions (log entries to user visible log is added)
        and revoking configuration for user (including Authenticator)
    """
    ret = {}
    username = kwargs.get("username")
    ret["auser"] = get_object_or_404(User, username=username)
    custom_log(request, "Admin: user details - %s" % username)

    if request.method == "POST":
        if request.POST.get("refresh"):
            custom_log(request, "Admin: refreshed %s" % username)
            get_and_refresh_user(username)
            messages.info(request, "Successfully refreshed: %s" % username)
        elif request.POST.get("signout"):
            custom_log(request, "Admin: sign out %s" % username)
            user = ret["auser"]
            user.sign_out_all(admin_logout=request.browser.user.username)
            log_entry = Log(user=user, message="%s signed out all sessions for this user" % request.browser.user.username, status="exclamation-circle")
            log_entry.save()
            messages.info(request, "Signed out all sessions for %s" % username)

        elif request.POST.get("revoke") == "yes":
            custom_log(request, "Admin: revoked %s" % username)
            user = ret["auser"]
            user.reset()
            user.sign_out_all(admin_logout=request.browser.user.username)
            log_entry = Log(user=user, message="%s revoked strong authentication settings and signed out all sessions" % request.browser.user.username, status="exclamation-circle")
            log_entry.save()
            messages.info(request, "Revoked Authenticator configuration for %s" % username)
        return HttpResponseRedirect("admin_frontend.views.userdetails", (username, ))

    ret["entries"] = Log.objects.filter(user=ret["auser"])[0:25]

    ret["duser"] = get_object_or_404(DjangoUser, username=username)
    ret["browsers"] = Browser.objects.filter(user=ret["auser"])
    ret["logins"] = BrowserLogin.objects.filter(user=ret["auser"])
    return render_to_response("admin_frontend/userdetails.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("logins", required_level=Browser.L_STRONG, admin_only=True)
def logins(request):
    """ Shows list of active logins for all users. """
    ret = {}
    custom_log(request, "Admin: list of active logins")
    entries = BrowserLogin.objects.filter(signed_out=False).filter(expires_at__lte=timezone.now())
    paginator = Paginator(logins, 100)
    page = request.GET.get("page")
    try:
        entries = paginator.page(page)
    except PageNotAnInteger:
        entries = paginator.page(1)
        page = 1
    except EmptyPage:
        entries = paginator.page(paginator.num_pages)
        page = paginator.num_pages
    entries.pagerange = range(max(1, entries.number - 5), min(paginator.num_pages, entries.number + 5))
    ret["logins"] = logins

    return render_to_response("admin_frontend/logins.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("browsers", required_level=Browser.L_STRONG, admin_only=True)
def browsers(request):
    """ Shows list of all browsers.
    TODO: pagination
    """
    ret = {}
    custom_log(request, "Admin: list of browsers")
    ret["browsers"] = Browser.objects.all()
    return render_to_response("admin_frontend/browsers.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("browserdetails", required_level=Browser.L_STRONG, admin_only=True)
def browserdetails(request, **kwargs):
    """ Shows details for a single browser """
    ret = {}
    bid_public = kwargs.get("bid_public")
    ret["abrowser"] = get_object_or_404(Browser, bid_public=bid_public)
    ret["logins"] = BrowserLogin.objects.filter(browser=ret["abrowser"])
    ret["entries"] = Log.objects.filter(bid_public=bid_public)[0:100]
    username = None
    if ret["abrowser"].user:
        username = ret["abrowser"].user.username
    custom_log(request, "Admin: browser details for %s (%s)" % (bid_public, username))
    return render_to_response("admin_frontend/browserdetails.html", ret, context_instance=RequestContext(request))

@require_http_methods(["GET"])
@protect_view("logs", required_level=Browser.L_STRONG, admin_only=True)
def logs(request, **kwargs):
    """ Shows log entries for browser, user or for all users """
    ret = {}
    custom_log(request, "Admin: logs")
    bid_public = kwargs.get("bid_public")
    username = kwargs.get("username")
    if bid_public:
        entries = Log.objects.filter(bid_public=bid_public)
        username = None
        try:
            ret["abrowser"] = Browser.objects.get(bid_public=bid_public)
            if ret["abrowser"].user:
                username = ret["abrowser"].user.username
        except Browser.DoesNotExist:
            ret["missing_browser"] = True
        custom_log(request, "Admin: entries for %s (%s)" % (bid_public, username))

    elif username:
        ret["auser"] = get_object_or_404(User, username=username)
        entries = Log.objects.filter(user=ret["auser"])
        custom_log(request, "Admin: entries for %s" % username)
    else:
        custom_log(request, "Admin: all entries")
        entries = Log.objects.all()

    paginator = Paginator(entries, 100)
    page = request.GET.get("page")
    try:
        entries = paginator.page(page)
    except PageNotAnInteger:
        entries = paginator.page(1)
        page = 1
    except EmptyPage:
        entries = paginator.page(paginator.num_pages)
        page = paginator.num_pages
    entries.pagerange = range(max(1, entries.number - 5), min(paginator.num_pages, entries.number + 5))
    ret["entries"] = entries


    return render_to_response("admin_frontend/logs.html", ret, context_instance=RequestContext(request))
