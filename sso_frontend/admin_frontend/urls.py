from django.conf.urls import patterns, url

urlpatterns = patterns('admin_frontend.views',
    url(r'^admin_/$', 'admin_indexview'),
    url(r'^admin_/users$', 'admin_users'),
    url(r'^admin_/user/(?P<username>(.+))$', 'admin_userdetails'),
    url(r'^admin_/logins$', 'admin_logins'),
    url(r'^admin_/browsers$', 'admin_browsers'),
    url(r'^admin_/browser/(?P<bid_public>(.+))$', 'admin_browserdetails'),
    url(r'^admin_/logs$', 'admin_logs'),
    url(r'^admin_/log/browser/(?P<bid_public>(.+))$', 'admin_logs', name="browser_logs"),
    url(r'^admin_/log/user/(?P<username>(.+))$', 'admin_logs', name="user_logs"),
)
