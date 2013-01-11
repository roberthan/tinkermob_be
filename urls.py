from django.conf.urls.defaults import patterns, include, url
from core.api import *
# Uncomment the next two lines to enable the admin:
from django.contrib import admin
from djrill import DjrillAdminSite

admin.site = DjrillAdminSite()
admin.autodiscover()

urlpatterns = patterns('',
#    url(r'^$', 'sleepyswan.core.views.IndexView'),
#    #        IndexView.as_view(),
#    #        name='index'),
#    url(r'^(?P<pk>\d+)/$',
#        DetailView.as_view(),
#        name="detail"),
    (r'^api/', include(v1.urls)),
#    (r'^login/', 'stacktest.base.views.userlogin'),
    (r'^image_upload/', 'sleepyswan.core.views.postImage'),
    (r'^auth/is_unique', 'sleepyswan.core.views.isUnique'),
    (r'^auth/join', 'sleepyswan.core.views.join'),
    (r'^auth/logout', 'sleepyswan.core.views.logoutView'),
#    (r'^auth/fb', 'sleepyswan.core.views.authFB'),
    (r'^auth/', 'sleepyswan.core.views.authUser'),
    (r'^test/', 'sleepyswan.core.views.postTest'),
    (r'^password/reset/$', 'sleepyswan.core.views.resetPassword'),
    (r'^password/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$', 'sleepyswan.core.views.passwordResetConfirm'),
#     {'post_reset_redirect' : '/accounts/password/done/'}),
#    (r'^password/done/$', 'django.contrib.auth.views.password_reset_complete'),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)
