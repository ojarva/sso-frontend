from django.conf.urls import patterns, url

urlpatterns = patterns('cspreporting.views',
    url(r'^csp-report(.*)$', 'log_report'),
    url(r'^view-csp-reports$', 'view_reports'),
    url(r'^view-csp-warnings$', 'view_warnings'),
    url(r'^test-csp(.*)$', 'test_csp'),
)
