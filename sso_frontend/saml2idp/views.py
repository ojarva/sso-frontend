# Python imports:
import base64
import logging
import time
import uuid

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

from login_frontend.utils import custom_redirect

def _generate_response(request, processor):
    """
    Generate a SAML response using processor and return it in the proper Django
    response.
    """
    try:
        tv = processor.generate_response()
    except exceptions.UserNotAuthorized:
        return render_to_response('saml2idp/invalid_user.html',
                                  context_instance=RequestContext(request))


    return custom_redirect("login_frontend.providers.internal_login", {"next": tv.get("next")})

def xml_response(request, template, tv):
    return render_to_response(template, tv, mimetype="application/xml")

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
        return render_to_response('saml2idp/error.html', {"missing_fields": True},
                                  context_instance=RequestContext(request))

    # Store these values now, because Django's login cycle won't preserve them.
    request.session['SAMLRequest'] = source['SAMLRequest']
    request.session['RelayState'] = source['RelayState']
    return redirect('login_process')

@login_required
def login_init(request, resource, **kwargs):
    """
    Initiates an IdP-initiated link to a simple SP resource/target URL.
    """
    sp_config = metadata.get_config_for_resource(resource)
    proc_path = sp_config['processor']
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
    logging.debug("Request: %s" % request)
    proc = registry.find_processor(request)
    return _generate_response(request, proc)

@csrf_exempt
def logout(request):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (SalesForce and others use this method,
    though it's technically not SAML 2.0).
    """
    return custom_redirect("login_frontend.views.logoutview", request.GET)

@login_required
@csrf_exempt
def slo_logout(request):
    """
    Receives a SAML 2.0 LogoutRequest from a Service Provider,
    logs out the user and returns a standard logged-out page.
    """

    if "SAMLRequest" not in request.POST:
        return render_to_response('saml2idp/error.html', {"missing_fields": True},
                                  context_instance=RequestContext(request))

    return custom_redirect("login_frontend.views.logoutview", request.GET)
    request.session['SAMLRequest'] = request.POST['SAMLRequest']
    #TODO: Parse SAML LogoutRequest from POST data, similar to login_process().
    #TODO: Add a URL dispatch for this view.
    #TODO: Modify the base processor to handle logouts?
    #TODO: Combine this with login_process(), since they are so very similar?
    #TODO: Format a LogoutResponse and return it to the browser.
    #XXX: For now, simply log out without validating the request.

def descriptor(request):
    """
    Replies with the XML Metadata IDSSODescriptor.
    """
    idp_config = saml2idp_metadata.SAML2IDP_CONFIG
    entity_id = config['issuer']
    slo_url = request.build_absolute_uri(reverse('logout'))
    sso_url = request.build_absolute_uri(reverse('login_begin'))
    pubkey = xml_signing.load_cert_data(config['certificate_file'])
    tv = {
        'entity_id': entity_id,
        'cert_public_key': pubkey,
        'slo_url': slo_url,
        'sso_url': sso_url,

    }
    return xml_response(request, 'saml2idp/idpssodescriptor.xml', tv,
                                context_instance=RequestContext(request))
