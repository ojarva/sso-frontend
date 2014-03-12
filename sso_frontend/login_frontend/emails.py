from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.template import RequestContext
from login_frontend.models import BrowserUsers, Browser
import html2text
import logging

def send_email(subject, html_content, to):

    html = html2text.HTML2Text()
    text_content = text_content = html.handle(html_content)
    from_email = settings.NOTICES_FROM_EMAIL
    msg = EmailMultiAlternatives(subject, text_content, from_email, [to], headers = {"Reply-To": settings.ADMIN_CONTACT_EMAIL})
    msg.attach_alternative(html_content, "text/html")
    if not settings.SEND_EMAILS:
        if settings.DEBUG:
            print "Sending notices is disabled. Did not send email to %s with subject '%s'" % (to, subject)
            print msg
            print
        return
    return msg.send()

def new_emergency_generated_notify(request, codes):
    ret = {}
    ret["remote_ip"] = request.remote_ip
    ret["codes"] = codes
    html_content = render_to_string("emails/emergency_generated.html", ret, context_instance=RequestContext(request))
    send_email("New emergency codes configured for your account", html_content, request.browser.user.email)


def emergency_used_notify(request, codes):
    ret = {}
    ret["remote_ip"] = request.remote_ip
    ret["codes"] = codes
    html_content = render_to_string("emails/emergency_used.html", ret, context_instance=RequestContext(request))
    send_email("Emergency code was used to access your account", html_content, request.browser.user.email)


def new_authenticator_notify(request):
    ret = {}
    ret["authenticator_id"] = request.browser.user.strong_authenticator_id
    ret["remote_ip"] = request.remote_ip
    html_content = render_to_string("emails/new_authenticator.html", ret, context_instance=RequestContext(request))
    send_email("New Authenticator configured to your account", html_content, request.browser.user.email)


def new_device_notify(request, auth_system):
    try:
        browser_user = BrowserUsers.objects.get(browser=request.browser, user=request.browser.user)
        if int(browser_user.max_auth_level) >= int(Browser.L_STRONG):
            return False
    except BrowserUsers.DoesNotExist:
        pass

    ret = {}
    ret["remote_ip"] = request.remote_ip
    if auth_system == "sms":
        ret["sms_used"] = True
    elif auth_system == "authenticator":
        ret["authenticator_used"] = True
    html_content = render_to_string("emails/new_device.html", ret, context_instance=RequestContext(request))
    send_email("Login from unrecognized device/browser", html_content, request.browser.user.email)
