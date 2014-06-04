from django.conf.urls import patterns, url

urlpatterns = patterns('admin_frontend.views',
    url(r'^ping/internal/admin_/indexview$', 'indexview', {"body_only": True}, name="admin-indexview-body"),
    url(r'^admin_/$', 'indexview'),
    url(r'^admin_/users$', 'users'),
    url(r'^admin_/user/(?P<username>(.+))$', 'userdetails'),
    url(r'^admin_/logins$', 'logins'),
    url(r'^admin_/yubikeys$', 'yubikeys'),
    url(r'^admin_/browsers$', 'browsers'),
    url(r'^admin_/browser/(?P<bid_public>(.+))$', 'browserdetails'),
    url(r'^admin_/logs$', 'logs'),
    url(r'^admin_/log/browser/(?P<bid_public>(.+))$', 'logs', name="browser_logs"),
    url(r'^admin_/log/user/(?P<username>(.+))$', 'logs', name="user_logs"),
    url(r'^admin_/search$', 'search'),
)
