from django.conf.urls import patterns, url
from django.views.generic import TemplateView

urlpatterns = patterns('datacollection.views',
    url(r'^data/location$', 'index_location_only'),
    url(r'^data$', 'index'),
    url(r'^datacollection/get_uptime$', TemplateView.as_view(template_name="datacollection/get_uptime.html"), name='get_uptime'),
    url(r'^data/location$', 'location'),
    url(r'^data/location_only$', 'location_only'),
    url(r'^data/browser_details$', 'browser_details'),
)
