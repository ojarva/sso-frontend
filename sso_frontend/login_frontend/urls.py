from django.conf.urls import patterns, url
from django.views.generic import TemplateView
from django.conf import settings

urlpatterns = patterns('login_frontend.views',
    url(r'^$', 'main_redir'),
    url(r'^index.php$', 'indexview'),
    url(r'^index$', 'indexview', name='index'),

    url(r'^debug', 'report_problem'),
    url(r'^report/problem', 'report_problem'),
    url(r'^download/location/kml', 'get_locations_kml'),
    url(r'^name_your_browser$', 'name_your_browser'),
    url(r'^sessions$', 'sessions'),
    url(r'^ping/internal/js$', 'automatic_ping', {"internal": True}),
    url(r'^ping/external/js$', 'automatic_ping', {"external": True}),
    url(r'^ping/internal/img$', 'automatic_ping', {"internal": True, "img": True}),
    url(r'^ping/external/img$', 'automatic_ping', {"external": True, "img": True}),
    url(r'^ping/location$', 'store_location'),
    url(r'^configure$', 'configure'),
    url(r'^view_log$', 'view_log'),
    url(r'^view_log/(?P<bid_public>(.+))$', 'view_log'),
    url(r'^configure/authenticator$', 'configure_authenticator'),
    url(r'^configure/get/authenticator_qr/(?P<single_use_code>(.+))$', 'get_authenticator_qr'),
    url(r'^configure/get/emergency_codes/image/(?P<single_use_code>(.+))$', 'get_emergency_codes_image'),
    url(r'^configure/get/emergency_codes/pdf/(?P<single_use_code>(.+))$', 'get_emergency_codes_pdf'),
    url(r'^introduction$', TemplateView.as_view(template_name="login_frontend/introduction.html"), name='introduction'),
    url(r'^developer_introduction$', TemplateView.as_view(template_name="login_frontend/developer_introduction.html"), name='developer_introduction'),
    url(r'^robots.txt$', TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    url(r'^download/pubkey/(?P<service>(.+))$', 'get_pubkey'),

    # timesync
    url(r'^timesync$', 'timesync'),
    url(r'^timesync/(?P<browser_random>(\d+))/(?P<browser_timezone>(.+))/(?P<browser_time>(\d+))$', 'timesync'),
    url(r'^timesync/(?P<browser_random>(\d+))/(?P<browser_timezone>(.+))/(?P<browser_time>(\d+))/(?P<last_server_time>(\d+))$', 'timesync'),
    url(r'^timesync/(?P<browser_random>(\d+))/(?P<browser_timezone>(.+))/(?P<browser_time>(\d+))/(?P<last_server_time>(\d+))/(?P<command>(.+))$', 'timesync'),
)

urlpatterns += patterns('login_frontend.authentication_views',
    # First factor authentication
    url(r'^first$', 'firststepauth'),
    url(r'^first/password$', 'authenticate_with_password'),

    # Second factor authentication
    url(r'^second$', 'secondstepauth'),
    url(r'^second/authenticator$', 'authenticate_with_authenticator'),
    url(r'^second/sms$', 'authenticate_with_sms'),
    url(r'^second/emergency$', 'authenticate_with_emergency'),
    url(r'^urlauth/(?P<sid>(.+))$', 'authenticate_with_url'),

    # logout
    url(r'^logout.php$', 'logoutview'),
    url(r'^logout$', 'logoutview', name='logout'),
)

urlpatterns += patterns('login_frontend.providers',
    # SSO providers
    url(r'^pubtkt$', 'pubtkt'),
    url(r'^internal_login$', 'internal_login'),
)

if settings.FAKE_TESTING:
    urlpatterns += patterns('login_frontend.error_tests',
       url(r'^errors/400', 'raise_400'),
       url(r'^errors/403', 'raise_403'),
       url(r'^errors/404', 'raise_404'),
       url(r'^errors/500', 'raise_500'),
    )
