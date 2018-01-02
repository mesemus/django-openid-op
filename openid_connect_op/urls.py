from django.conf.urls import url
from django.contrib.auth.views import LogoutView

from openid_connect_op.views.client_configuration_view import ClientConfigurationView
from openid_connect_op.views.consent_view import ConsentView
from openid_connect_op.views.logout_request_view import LogoutRequestView
from .views.dynamic_registration_view import DynamicClientRegistrationView
from .views.jwks_view import JWKSView
from .views.userinfo_request_view import UserInfoView
from .views.wellknown import WellKnownView
from .views.authentication_request_view import AuthenticationRequestView
from .views.token_request_view import TokenRequestView

urlpatterns = [
    url('^openid/authorize', AuthenticationRequestView.as_view(), name='authorize'),
    url('^openid/token', TokenRequestView.as_view(), name='token'),
    url('^openid/userinfo', UserInfoView.as_view(), name='userinfo'),
    url('^openid/register', DynamicClientRegistrationView.as_view(), name='register'),
    url('^openid/client_configuration/(?P<client_id>.*)', ClientConfigurationView.as_view(), name='client_configuration'),
    url('^openid/jwks', JWKSView.as_view(), name='jwks'),
    url('^openid/logout', LogoutRequestView.as_view(), name='logout'),
    url('^openid/consent/(?P<client_id>\d+)/$', ConsentView.as_view(), name='consent'),
    url('^.well-known/openid-configuration', WellKnownView.as_view(), name='wellknown')
]

app_name = 'openid_connect_op'
