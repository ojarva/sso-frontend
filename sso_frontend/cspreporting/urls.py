from django.conf.urls import patterns, url

urlpatterns = patterns('cspreporting.views',
    url(r'^csp-report(.*)$', 'log_report'),
    url(r'^view-reports$', 'view_reports'),
    url(r'^test-csp(.*)$', 'test_csp'),
)
