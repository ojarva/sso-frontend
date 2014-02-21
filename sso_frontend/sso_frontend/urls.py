from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^', include('openid_provider.urls')),
    url(r'^', include('login_frontend.urls')),
    url(r'^', include('admin_frontend.urls')),
    url(r'^', include('cspreporting.urls')),
    url(r'^', include('saml2idp.urls')),
    # url(r'^sso_frontend/', include('sso_frontend.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)

handler400 = "login_frontend.error_views.error_400"
handler403 = "login_frontend.error_views.error_403"
handler404 = "login_frontend.error_views.error_404"
handler500 = "login_frontend.error_views.error_500"
