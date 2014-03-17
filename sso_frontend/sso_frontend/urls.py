from django.conf.urls import patterns, include, url
from django_statsd.urls import urlpatterns as statsd_patterns

urlpatterns = patterns('',
    # Examples:
    url(r'^', include('openid_provider.urls')),
    url(r'^', include('login_frontend.urls')),
    url(r'^', include('admin_frontend.urls')),
    url(r'^', include('cspreporting.urls')),
    url(r'^', include('saml2idp.urls')),
    url(r'^', include('datacollection.urls')),

    url(r'^services/timing/', include(statsd_patterns)),
)

handler400 = "login_frontend.error_views.error_400"
handler403 = "login_frontend.error_views.error_403"
handler404 = "login_frontend.error_views.error_404"
handler500 = "login_frontend.error_views.error_500"
