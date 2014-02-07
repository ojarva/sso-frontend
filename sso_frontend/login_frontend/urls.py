from django.conf.urls import patterns, url
from django.views.generic import TemplateView

from login_frontend import views
from login_frontend import providers

urlpatterns = patterns('',
    url(r'^$', views.main_redir),
    url(r'^index$', views.indexview, name='index'),

    # First factor authentication
    url(r'^first$', views.firststepauth),
    url(r'^first/password$', views.authenticate_with_password),

    # Second factor authentication
    url(r'^second$', views.secondstepauth),
    url(r'^second/authenticator$', views.authenticate_with_authenticator),
    url(r'^second/sms$', views.authenticate_with_sms),
    url(r'^second/emergency$', views.authenticate_with_emergency),

    # SSO providers
    url(r'^pubtkt$', providers.pubtkt),
    url(r'^internal_login$', providers.internal_login),

    # Other URLs
    url(r'^configure$', views.configure_strong),
    url(r'^configure_authenticator$', views.configure_authenticator),
    url(r'^configure_authenticator_qr/(?P<single_use_code>(.+))$', views.get_authenticator_qr),
    url(r'^logout$', views.logoutview, name='logout'),
    url(r'^introduction$', TemplateView.as_view(template_name="introduction.html"), name='introduction'),
)
