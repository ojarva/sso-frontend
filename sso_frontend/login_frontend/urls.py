from django.conf.urls import patterns, url

from login_frontend import views


urlpatterns = patterns('',
    url(r'^$', views.indexview, name='index'),
    url(r'^logout$', views.logoutview, name='logout'),

)
