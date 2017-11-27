import base64
import traceback

from django.http import HttpResponseBadRequest
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from ratelimit.mixins import RatelimitMixin

from . import OAuthRequestMixin
from .errors import OAuthError
from .parameters import AuthenticationParameters, TokenParameters


# section 4.1.3 of OAUTH 2.0
class TokenRequestView(OAuthRequestMixin, RatelimitMixin, View):
    ratelimit_key    = 'ip'
    ratelimit_rate   = '10/m'
    ratelimit_block  = True
    ratelimit_method = 'ALL'

    # noinspection PyAttributeOutsideInit
    def dispatch(self, request, *args, **kwargs):
        if request.method not in ('GET', 'POST'):
            return HttpResponseBadRequest('Only GET or POST are supported on OpenID endpoint')

        try:
            self.parse_request_parameters(request, TokenParameters)

            authentication_parameters = AuthenticationParameters.unpack(self.request_parameters.code)

            client = self.authenticate_client(request)

            self.validate_redirect_uri(authentication_parameters)

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })
        except:
            traceback.print_exc()
            return self.oauth_send_answer(request, {
                'error': 'unknown_error',
                'error_description': 'Unknown error occurred at %s, check the logs' % timezone.now()
            })

    def validate_redirect_uri(self, authentication_parameters):
        auth_redirect_uri = authentication_parameters.redirect_uri
        token_redirect_uri = self.request_parameters.redirect_uri
        if auth_redirect_uri and auth_redirect_uri != token_redirect_uri:
            raise OAuthError(error='invalid_request_uri',
                             error_description='redirect_uri used in authentication but not for token')
        if not auth_redirect_uri and token_redirect_uri:
            raise OAuthError(error='invalid_request_uri',
                             error_description='redirect_uri not used in authentication but passed for token')

    def authenticate_client(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Basic '):
            return self.authenticate_with_http_basic(auth_header)
        if self.request_parameters.client_secret:
            return self.authenticate_with_client_secret()
        if self.request_parameters.client_id:
            client = self.try_null_authentication()
            if client:
                return client
        raise OAuthError(error='unsupported_authentication_method',
                         error_description='Only HTTP Basic auth or client_secret is supported')

    def authenticate_with_http_basic(self, auth_header):
        username, password = base64.b64decode(auth_header[6:].strip()).decode('utf-8').split(':', 1)
        try:
            client = self.openid_client_model.objects.get(client_username=username)
            if not client.check_client_password(password):
                raise OAuthError(error='unauthorized_client', error_description='Bad username or password')

            if self.request_parameters.client_id and client.client_id != self.request_parameters.client_id:
                raise OAuthError(error='invalid_request',
                                 error_description='client_id does not match with authorized client')

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_BASIC:
                raise OAuthError(error='invalid_request',
                                 error_description='Used HTTP Basic but client configured to different auth')
            return client

        except self.openid_client_model.DoesNotExist:
            raise OAuthError(error='unauthorized_client', error_description='Bad username or password')

    def authenticate_with_client_secret(self):
        if not self.request_parameters.client_id:
            raise OAuthError(error='invalid_request',
                             error_description='Need client_id when using client_secret')
        try:
            client = self.openid_client_model.objects.get(client_id=self.request_parameters.client_id)

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_POST:
                raise OAuthError(error='invalid_request',
                                 error_description='Client not configured to use POST authentication')

            if client.check_client_password(self.request_parameters.client_secret):
                return client

        except self.openid_client_model.DoesNotExist:
            pass

        raise OAuthError(error='unauthorized_client', error_description='Bad client_id or client_secret')

    def try_null_authentication(self):
        if not self.request_parameters.client_id:
            return None

        try:
            client = self.openid_client_model.objects.get(client_id=self.request_parameters.client_id)

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_NONE:
                return None

            return client
        except self.openid_client_model.DoesNotExist:
            pass

