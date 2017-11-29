import base64
import traceback

from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from openid_connect_op.models import OpenIDClient, OpenIDKey
from openid_connect_op.utils.jwt import JWTTools
from . import OAuthRequestMixin
from .errors import OAuthError
from .parameters import AuthenticationParameters, TokenParameters
from ..models import OpenIDToken


# section 4.1.3 of OAUTH 2.0
class TokenRequestView(OAuthRequestMixin, RatelimitMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'
    use_redirect_uri = False
    attribute_parsing_error = 'invalid_request'

    # noinspection PyAttributeOutsideInit
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        if request.method not in ('GET', 'POST'):
            return HttpResponseBadRequest('Only GET or POST are supported on OpenID endpoint')

        # noinspection PyBroadException
        try:
            self.parse_request_parameters(request, TokenParameters)

            client = self.authenticate_client(request)

            if self.request_parameters.grant_type == {'authorization_code'}:
                return self.process_authorization_code_grant_type(request, client)
            elif self.request_parameters.grant_type == {'refresh_token'}:
                return self.process_refresh_token(request, client)
            else:
                raise OAuthError(error='invalid_request_uri',
                                 error_description='Invalid grant type %s' % self.request_parameters.grant_type)

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })
        except BaseException:
            traceback.print_exc()
            return self.oauth_send_answer(request, {
                'error': 'unknown_error',
                'error_description': 'Unknown error occurred at %s, check the logs' % timezone.now()
            })

    def process_authorization_code_grant_type(self, request, client):

        if not self.request_parameters.code:
            raise OAuthError(error='invalid_request',
                             error_description='Required parameter with name "code" is not present')

        try:
            authentication_parameters = AuthenticationParameters.unpack(
                self.request_parameters.code.encode('ascii'), prefix=b'AUTH',
                key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY)
            )
        except ValueError as e:
            raise OAuthError(error='unauthorized_client', error_description=str(e))

        self.validate_redirect_uri(authentication_parameters)

        return self.generate_tokens_and_oauth_response(authentication_parameters, client, request)

    def process_refresh_token(self, request, client):
        if not self.request_parameters.refresh_token:
            raise OAuthError(error='invalid_request',
                             error_description='Required parameter with name "refresh_token" is not present')
        try:
            refresh_token = OpenIDToken.objects.get(
                token_hash=OpenIDToken.get_token_hash(self.request_parameters.refresh_token))
            if refresh_token.expiration < timezone.now():
                raise OAuthError(error='invalid_grant', error_description='Refresh token expired')
        except OpenIDToken.DoesNotExist:
            raise OAuthError(error='invalid_grant', error_description='No such token was found')

        original_access_token = refresh_token.root_token
        authentication_parameters = AuthenticationParameters(original_access_token.token_data)
        # noinspection PyTypeChecker
        return self.generate_tokens_and_oauth_response(authentication_parameters, client, request)

    def generate_tokens_and_oauth_response(self, authentication_parameters, client, request):
        access_token_ttl = getattr(settings, 'OPENID_DEFAULT_ACCESS_TOKEN_TTL', 3600)
        refresh_token_ttl = getattr(settings, 'OPENID_DEFAULT_REFRESH_TOKEN_TTL', 3600 * 10)
        user = User.objects.get(username=authentication_parameters.username)

        access_token, db_access_token = OpenIDToken.create_token(
            client,
            OpenIDToken.TOKEN_TYPE_ACCESS_BEARER_TOKEN,
            authentication_parameters.to_dict(),
            access_token_ttl,
            user,
        )
        refresh_token, refresh_db_token = OpenIDToken.create_token(
            client,
            OpenIDToken.TOKEN_TYPE_REFRESH_TOKEN,
            {},
            refresh_token_ttl,
            user,
            root_db_token=db_access_token
        )
        id_token = self.create_id_token(request, client, authentication_parameters, db_access_token, user)
        return self.oauth_send_answer(request, {
            'access_token': access_token,
            'token_type': 'Bearer',
            'refresh_token': refresh_token,
            'expires_in': access_token_ttl,
            'id_token': id_token
        })

    def validate_redirect_uri(self, authentication_parameters):
        auth_redirect_uri = authentication_parameters.redirect_uri
        token_redirect_uri = self.request_parameters.redirect_uri
        if auth_redirect_uri and auth_redirect_uri != token_redirect_uri:
            raise OAuthError(error='invalid_request_uri',
                             error_description='redirect_uri does not match the one used in /authorize endpoint')
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
            client = OpenIDClient.objects.get(client_id=username)
            if not client.check_client_secret(password):
                raise OAuthError(error='unauthorized_client', error_description='Bad username or password')

            if self.request_parameters.client_id and client.client_id != self.request_parameters.client_id:
                raise OAuthError(error='invalid_request',
                                 error_description='client_id does not match with authorized client')

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_BASIC:
                raise OAuthError(error='invalid_request',
                                 error_description='Used HTTP Basic but client configured to different auth')
            return client

        except OpenIDClient.DoesNotExist:
            raise OAuthError(error='unauthorized_client', error_description='Bad username or password')

    def authenticate_with_client_secret(self):
        if not self.request_parameters.client_id:
            raise OAuthError(error='invalid_request',
                             error_description='Need client_id when using client_secret')
        try:
            client = OpenIDClient.objects.get(client_id=self.request_parameters.client_id)

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_POST:
                raise OAuthError(error='invalid_request',
                                 error_description='Client not configured to use POST authentication')

            if client.check_client_secret(self.request_parameters.client_secret):
                return client

        except OpenIDClient.DoesNotExist:
            pass

        raise OAuthError(error='unauthorized_client', error_description='Bad client_id or client_secret')

    def try_null_authentication(self):
        if not self.request_parameters.client_id:
            return None

        try:
            client = OpenIDClient.objects.get(client_id=self.request_parameters.client_id)

            if client.client_auth_type != client.CLIENT_AUTH_TYPE_NONE:
                return None

            return client
        except OpenIDClient.DoesNotExist:
            pass

    @staticmethod
    def create_id_token(request, client, authentication_parameters, db_access_token, user):
        id_token = {
            "iss": request.build_absolute_uri('/'),
            "sub": request.user.username,
            "aud": [client.client_id],
            "exp": int(db_access_token.expiration.timestamp()),
            # the time at which user was authenticated - we do not have this stored anywhere ...
            # "auth_time": 1311280969,

            # level of trustability of the login
            # "acr": "urn:mace:incommon:iap:silver",

            # names of authentication methods that were used to login this user
            # "amr": None,

            # the audience is the same as the acceptor of this token, so omitting the azp
            # "azp": None
        }

        if authentication_parameters.nonce:
            id_token['nonce'] = authentication_parameters.nonce

        token = JWTTools.generate_jwt(id_token)

        # save the token to the database
        OpenIDToken.create_token(client, OpenIDToken.TOKEN_TYPE_ID_TOKEN, {
            'token': token
        }, db_access_token.expiration, user, db_access_token)

        return token
