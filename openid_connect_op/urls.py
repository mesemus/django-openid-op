from django.conf.urls import url

from .views.authentication_request import AuthenticationRequestView
from .views.token_request import TokenRequestView

urlpatterns = [
    url('^authorize/', AuthenticationRequestView.as_view()),
    url('^token/', TokenRequestView.as_view())
]

app_name = 'openid_connect_op'
