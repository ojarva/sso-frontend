# Python imports:
import base64
import logging
import time
import uuid
import urllib
import urlparse

# Django/other library imports:
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt

# saml2idp app imports:
import exceptions
import metadata
import registry
import saml2idp_metadata
import xml_signing

from login_frontend.utils import redirect_with_get_params
from login_frontend.models import BrowserLogin, add_user_log

from django.utils import timezone
import os
import sys
import statsd
from utils import get_destination_service, parse_google_saml
from django.core.cache import get_cache
import logging

dcache = get_cache("default")

log = logging.getLogger(__name__)

sd = statsd.StatsClient()

@sd.timer("saml2idp.views.custom_log")
def custom_log(request, message, **kwargs):
    """ Automatically logs username, remote IP and bid_public """
    try:
        raise Exception
    except:
        stack = sys.exc_info()[2].tb_frame.f_back
    if stack is not None:
        stack = stack.f_back
    while hasattr(stack, "f_code"):
        co = stack.f_code
        filename = os.path.normcase(co.co_filename)
        filename = co.co_filename
        lineno = stack.f_lineno
        co_name = co.co_name
        break

    level = kwargs.get("level", "info")
    method = getattr(log, level)
    remote_addr = request.remote_ip
    bid_public = username = ""
    if hasattr(request, "browser") and request.browser:
        bid_public = request.browser.bid_public
        if request.browser.user:
            username = request.browser.user.username
    method("[%s:%s:%s] %s - %s - %s - %s", filename, lineno, co_name,
                            remote_addr, username, bid_public, message)


def _generate_response(request, processor):
    """
    Generate a SAML response using processor and return it in the proper Django
    response.
    """
    try:
        tv = processor.generate_response()
    except exceptions.UserNotAuthorized:
        custom_log(request, "Unauthorized to sign in", level="warn")
        return render_to_response('saml2idp/invalid_user.html',
                                  context_instance=RequestContext(request))


    return_url = get_destination_service(tv["acs_url"])
    saml_id = request.GET.get("saml_id")
    if saml_id:
        tmp = dcache.get("saml-return-%s" % saml_id)
        if tmp:
            return_url = "%s - %s" % (return_url, tmp)
        dcache.delete(["saml-return-%s" % saml_id, "saml-SAMLRequest-%s" % saml_id, "saml-RelayState-%s" % saml_id])


    # Update/add BrowserLogin
    try:
        (browser_login, created) = BrowserLogin.objects.get_or_create(user=request.browser.user, browser=request.browser, sso_provider="saml2", message=return_url, signed_out=False, remote_service=str(tv["acs_url"]), defaults={"auth_timestamp": timezone.now()})
        if not created:
            browser_login.auth_timestamp = timezone.now()
            browser_login.save()
    except BrowserLogin.MultipleObjectsReturned:
        custom_log(request, "Multiple BrowserLogin objects for user=%s, browser=%s, sso_provider=saml2, remote_service=%s" % (request.browser.user.username, request.browser.bid_public, tv["acs_url"]), level="error")

    custom_log(request, "Signed in with SAML to %s" % return_url, level="info")
    add_user_log(request, "Signed in with SAML to %s" % return_url, "share-square-o")

    custom_log(request, "Rendering login.html with tv=%s" % tv, level="debug")

    return render_to_response('saml2idp/login.html', tv,
                                context_instance=RequestContext(request))

def xml_response(request, template, tv, **kwargs):
    return render_to_response(template, tv, mimetype="application/xml", **kwargs)

@csrf_exempt
def login_begin(request, *args, **kwargs):
    """
    Receives a SAML 2.0 AuthnRequest from a Service Provider and
    stores it in the session prior to enforcing login.
    """
    if request.method == 'POST':
        source = request.POST
    else:
        source = request.GET

    if not ('SAMLRequest' in source and 'RelayState' in source):
        custom_log(request, "Invalid request: missing SAMLRequest or RelayState", level="info")
        return render_to_response('saml2idp/error.html', {"missing_fields": True},
                                  context_instance=RequestContext(request))

    # Store these values now, because Django's login cycle won't preserve them.

    saml_id = str(uuid.uuid4())

    return_url = None
    try:
        return_url = parse_google_saml(source["RelayState"])
    except Exception, e:
        log.error("URL parsing exception %s" % e)
    if return_url:
        dcache.set("saml-return-%s" % saml_id, return_url, 3600 * 12)
    dcache.set("saml-SAMLRequest-%s" % saml_id, source['SAMLRequest'], 3600 * 12)
    dcache.set("saml-RelayState-%s" % saml_id, source['RelayState'], 3600 * 12)
    custom_log(request, "Storing SAMLRequest=%s and RelayState=%s with saml_id=%s" % (source['SAMLRequest'], source['RelayState'], saml_id), level="debug")
    return redirect_with_get_params("saml2idp.views.login_process", {"saml_id": saml_id})

@login_required
def login_init(request, resource, **kwargs):
    """
    Initiates an IdP-initiated link to a simple SP resource/target URL.
    """
    sp_config = metadata.get_config_for_resource(resource)
    proc_path = sp_config['processor']
    custom_log(request, "login_init: proc_path=%s" % proc_path, level="debug")
    proc = registry.get_processor(proc_path)
    try:
        linkdict = dict(metadata.get_links(sp_config))
        pattern = linkdict[resource]
    except KeyError:
        raise ImproperlyConfigured('Cannot find link resource in SAML2IDP_REMOTE setting: "%s"' % resource)
    is_simple_link = ('/' not in resource)
    if is_simple_link:
        simple_target = kwargs['target']
        url = pattern % simple_target
    else:
        url = pattern % kwargs
    proc.init_deep_link(request, sp_config, url)
    return _generate_response(request, proc)

@login_required
def login_process(request):
    """
    Processor-based login continuation.
    Presents a SAML 2.0 Assertion for POSTing back to the Service Provider.
    """
    #reg = registry.ProcessorRegistry()
    try:
        proc = registry.find_processor(request)
    except exceptions.NoRequestAvailable:
        return render_to_response("saml2idp/no_request_available.html", {}, context_instance=RequestContext(request))
    except exceptions.CannotHandleAssertion as ex:
        return render_to_response("saml2idp/error.html",
            { "assertion_failed": ex },
            context_instance=RequestContext(request))

    custom_log(request, "login_process: %s" % proc, level="debug")
    return _generate_response(request, proc)

@csrf_exempt
def logout(request):
    """
    Forwards SAML 2.0 logout URL to logout page.
    """
    custom_log(request, "Redirecting to logout page from GET logout", level="debug")
    return redirect_with_get_params("login_frontend.views.logoutview", request.GET)

@login_required
@csrf_exempt
def slo_logout(request):
    """
    Receives a SAML 2.0 LogoutRequest from a Service Provider,
    logs out the user and returns a standard logged-out page.
    """

    if "SAMLRequest" not in request.POST:
        custom_log(request, "Invalid request to logout page: missing SAMLRequest", level="warn")
        return render_to_response('saml2idp/error.html', {"missing_fields": True},
                                  context_instance=RequestContext(request))

    custom_log(request, "Redirecting to logout page from POST logout", level="debug")
    return redirect_with_get_params("login_frontend.views.logoutview", request.GET)

def descriptor(request):
    """
    Replies with the XML Metadata IDSSODescriptor.
    """
    idp_config = saml2idp_metadata.SAML2IDP_CONFIG
    entity_id = idp_config['issuer']
    slo_url = request.build_absolute_uri(reverse('logout'))
    sso_url = request.build_absolute_uri(reverse('login_begin'))
    pubkey = xml_signing.load_cert_data(idp_config['certificate_file'])
    tv = {
        'entity_id': entity_id,
        'cert_public_key': pubkey,
        'slo_url': slo_url,
        'sso_url': sso_url,

    }
    custom_log(request, "XML metadata IDSSODescriptor: %s" % tv, level="debug")
    return xml_response(request, 'saml2idp/idpssodescriptor.xml', tv,
                                context_instance=RequestContext(request))
