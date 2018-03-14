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

from openid_connect_op.models import OpenIDClient
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
            try:
                self.request_parameters.check_errors()
            except AttributeError as e:
                raise OAuthError(error=self.attribute_parsing_error, error_description=str(e))

            client = self.authenticate_client(request)

            if self.request_parameters.grant_type == {'authorization_code'}:
                return self.process_authorization_code_grant_type(request, client)
            elif self.request_parameters.grant_type == {'refresh_token'}:
                return self.process_refresh_token(request, client)
            else:
                raise OAuthError(error='invalid_request',
                                 error_description='Invalid grant type %s' % self.request_parameters.grant_type)

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })
        except BaseException as err:
            traceback.print_exc()
            if settings.DEBUG:
                return self.oauth_send_answer(request, {
                    'error': 'unknown_error',
                    'error_description': 'Unknown error: %s' % traceback.format_exc()
                })
            else:
                return self.oauth_send_answer(request, {
                    'error': 'unknown_error',
                    'error_description': 'Unknown error occurred at %s, check the logs' % timezone.now()
                })

    def process_authorization_code_grant_type(self, request, client):

        if not self.request_parameters.code:
            raise OAuthError(error='invalid_request',
                             error_description='Required parameter with name "code" is not present')

        authorization_token = OpenIDToken.objects.filter(
            token_hash=OpenIDToken.get_token_hash(self.request_parameters.code),
            client=client,
            token_type=OpenIDToken.TOKEN_TYPE_AUTH).first()

        if not authorization_token:
            raise OAuthError(error='unauthorized_client',
                             error_description='Authorization token not found')

        if authorization_token.expired:
            raise OAuthError(error='unauthorized_client',
                             error_description='Authorization token expired')

        authentication_parameters = AuthenticationParameters(authorization_token.token_data)

        # prevent reusing
        authorization_token.delete()

        self.validate_redirect_uri(authentication_parameters)

        return self.generate_tokens_and_oauth_response(authentication_parameters, client, request)

    def process_refresh_token(self, request, client):
        if not self.request_parameters.refresh_token:
            raise OAuthError(error='invalid_request',
                             error_description='Required parameter with name "refresh_token" is not present')
        try:
            refresh_token = OpenIDToken.objects.get(
                token_hash=OpenIDToken.get_token_hash(self.request_parameters.refresh_token),
                token_type=OpenIDToken.TOKEN_TYPE_REFRESH_TOKEN,
                client=client)
            if refresh_token.expired:
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
            raise OAuthError(error='invalid_request',
                             error_description='redirect_uri does not match the one used in /authorize endpoint')
        if not auth_redirect_uri and token_redirect_uri:
            raise OAuthError(error='invalid_request',
                             error_description='redirect_uri not used in authentication but passed for token')

    def authenticate_client(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Basic '):
            return self.authenticate_with_http_basic(auth_header)
        if self.request_parameters.client_assertion_type == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer':
            if not self.request_parameters.client_assertion:
                raise OAuthError(error='unsupported_authentication_method',
                                 error_description='Need client_assertion if client_assertion_type is jwt-bearer')
            return self.authenticate_with_jwt_bearer()
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

    def authenticate_with_jwt_bearer(self):
        assertion = self.request_parameters.client_assertion
        payload = JWTTools.unverified_jwt_payload(assertion)

        for req in ('sub', 'iss', 'aud', 'jti', 'exp'):
            if req not in payload:
                raise OAuthError(error='invalid_request',
                                 error_description='The assertion token must contain %s field' % req)

        if payload['iss'] != payload['sub']:
            raise OAuthError(error='invalid_request',
                             error_description='The assertion token\'s iss and sub fields differ')

        auri = self.request.build_absolute_uri(self.request.path)
        for aud in payload['aud']:
            if auri == aud:
                break
        else:
            raise OAuthError(error='invalid_request',
                             error_description='The assertion token is for audience %s, I am %s' % (
                             payload['aud'], auri))

        client = OpenIDClient.objects.filter(client_id=payload['iss']).first()
        if not client:
            raise OAuthError(error='invalid_request',
                             error_description='Client with id %s is not registered on this server' % payload['iss'])
        try:
            JWTTools.validate_jwt(assertion, client)
        except Exception as e:
            traceback.print_exc()
            print("debug: Client auth method", client.client_auth_type)
            raise OAuthError(error='invalid_request',
                             error_description='JWT validation failed: %s' % e)

        return client

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
            "sub": client.make_sub(settings.OPENID_SUB_PROVIDER(user, client)),
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
        }, db_access_token.expiration, user, db_access_token, token=token)

        return token
