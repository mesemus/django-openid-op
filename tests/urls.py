from django.conf.urls import include, url
from django.contrib import admin

from tests.views import ConsentView, IndexView
urlpatterns = [
    url('^admin/', admin.site.urls),
    url('^django/', include('django.contrib.auth.urls')),
    url('^', include('openid_connect_op.urls')),
    url('', include('social_django.urls', namespace='social')),
    # test views
    url('', include(
        (
            [
                url(r'^$', IndexView.as_view()),
            ],
            'test'
        ), namespace='test'))
]
