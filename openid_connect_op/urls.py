from django.conf.urls import url

from openid_connect_op.views.userinfo_request_view import UserInfoView
from openid_connect_op.views.wellknown import WellKnownView
from .views.authentication_request_view import AuthenticationRequestView
from .views.token_request_view import TokenRequestView

urlpatterns = [
    url('^openid/authorize', AuthenticationRequestView.as_view(), name='authorize'),
    url('^openid/token', TokenRequestView.as_view(), name='token'),
    url('^openid/userinfo', UserInfoView.as_view(), name='userinfo'),
    url('^.well-known/openid-configuration', WellKnownView.as_view(), name='wellknown')
]

app_name = 'openid_connect_op'
