from django.conf.urls import patterns, url
from django.views.generic import TemplateView

from login_frontend import views
from login_frontend import providers

urlpatterns = patterns('',
    url(r'^$', views.main_redir),
    url(r'^index.php$', views.indexview),
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
    url(r'^sessions$', views.sessions),
    url(r'^ping/internal/js$', views.js_ping, {"internal": True}),
    url(r'^configure$', views.configure_strong),
    url(r'^view_log$', views.view_log),
    url(r'^view_log/(?P<bid_public>(.+))$', views.view_log),
    url(r'^configure_authenticator$', views.configure_authenticator),
    url(r'^configure_authenticator_qr/(?P<single_use_code>(.+))$', views.get_authenticator_qr),
    url(r'^logout.php$', views.logoutview),
    url(r'^logout$', views.logoutview, name='logout'),
    url(r'^introduction$', TemplateView.as_view(template_name="login_frontend/introduction.html"), name='introduction'),
    url(r'^developer_introduction$', TemplateView.as_view(template_name="login_frontend/developer_introduction.html"), name='developer_introduction'),
    url(r'^get_pubkey/(?P<service>(.+))$', views.get_pubkey),
)
