from django.conf.urls import url

from openid_connect_op.views.authentication_request import AuthenticationRequestView

urlpatterns = [
    url('^authorize/', AuthenticationRequestView.as_view())
]

app_name = 'openid_connect_op'
