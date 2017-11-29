from django.conf.urls import include, url

from tests.views import ConsentView, IndexView

urlpatterns = [
    url('^django/', include('django.contrib.auth.urls')),
    url('^', include('openid_connect_op.urls')),
    url('', include('social_django.urls', namespace='social')),
    # test views
    url('', include(
        (
            [
                url(r'^openid/consent/(?P<client_id>\d+)/', ConsentView.as_view(), name='consent'),
                url(r'^', IndexView.as_view()),
            ],
            'test'
        ), namespace='test'))
]
