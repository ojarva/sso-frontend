"""
Django error views 
"""

from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.http import require_http_methods
from login_frontend.models import Browser
import logging
import redis

log = logging.getLogger(__name__)
r = redis.Redis()


@require_http_methods(["GET", "POST"])
def error_csrf(request, reason="", **kwargs):
    """ This is an error view for CSRF errors.
        Missing cookies warning is shown if user does not have a single cookie. """
    ret = {}
    if len(request.COOKIES) == 0:
        ret["no_cookies"] = True
    ret["reason"] = reason
    response = render_to_response("login_frontend/errors/csrf_fail.html", ret, context_instance=RequestContext(request))
    response.status_code = "403"
    response.reason_phrase = "Forbidden"
    return response

@require_http_methods(["GET", "POST"])
def error_400(request, **kwargs):
    """ View for 400 - Bad Request.
        All cookies are deleted, and user is signed out.
    """
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/400.html", ret, context_instance=RequestContext(request))

    # Upon bad request, delete all session data.
    if hasattr(request, "browser") and request.browser:
        request.browser.logout()

    response.delete_cookie(Browser.C_BID)
    response.delete_cookie(Browser.C_BID_PUBLIC)
    response.delete_cookie(Browser.C_BID_SESSION)
    response.delete_cookie("auth_pubtkt")
    response.delete_cookie("csrftoken")
    response.delete_cookie("sessionid")
    response.delete_cookie("slogin")
    response.status_code = "400"
    response.reason_phrase = "Bad Request"
    return response


@require_http_methods(["GET", "POST"])
def error_403(request, **kwargs):
    """ 403 - Forbidden. This is encountered with ratelimits, and when trying to access admin pages. """
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    if hasattr(request, "limited") and request.limited:
        ret["ratelimit"] = True
    response = render_to_response("login_frontend/errors/403.html", ret, context_instance=RequestContext(request))
    response.status_code = "403"
    response.reason_phrase = "Forbidden"
    return response


@require_http_methods(["GET", "POST"])
def error_404(request, **kwargs):
    """ Not found page. If public browser ID exists, it is shown on the page. """
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/404.html", ret, context_instance=RequestContext(request))
    response.status_code = "404"
    response.reason_phrase = "Not Found"
    return response


@require_http_methods(["GET", "POST"])
def error_500(request, **kwargs):
    """ Internal server error page. All errors preventing django from starting
        are handled by web server. """
    ret = {}
    ret["browser_public_bid"] = request.COOKIES.get(Browser.C_BID_PUBLIC)
    response = render_to_response("login_frontend/errors/500.html", ret, context_instance=RequestContext(request))
    response.status_code = "500"
    response.reason_phrase = "Internal Server Error"
    return response

