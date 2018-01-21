# section 4.1.3 of OAUTH 2.0
import hashlib
import json
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.urls import reverse

try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

from django.http import JsonResponse
from django.http.response import HttpResponseForbidden, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from openid_connect_op.decorators import access_token_required
from openid_connect_op.models import OpenIDToken, OpenIDClient
from openid_connect_op.views import OAuthRequestMixin, OAuthError
from openid_connect_op.views.parameters import DynamicClientRegistrationParameters


class DynamicClientRegistrationView(RatelimitMixin, OAuthRequestMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'

    @method_decorator(csrf_exempt)
    @method_decorator(access_token_required(disabled_settings='OPENID_DYNAMIC_CLIENT_REGISTRATION_DISABLE_ACCESS_TOKEN'))
    def dispatch(self, request, *args, **kwargs):
        if request.openid_access_token and \
                        request.openid_access_token.token_type != OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION:
            return HttpResponseForbidden('Can not use this token to access dynamic registration view')

        if request.method != 'POST':
            return HttpResponseBadRequest('Only POST is allowed')

        try:
            self.parse_request_parameters(request, DynamicClientRegistrationParameters)
            try:
                self.request_parameters.check_errors()
            except AttributeError as e:
                raise OAuthError(error=self.attribute_parsing_error, error_description=str(e))

            pairwise_key = None
            if self.request_parameters.sector_identifier_uri:
                try:
                    redirect_uris = requests.get(self.request_parameters.sector_identifier_uri)
                    redirect_uris = redirect_uris.json()
                    for ru in self.request_parameters.redirect_uris:
                        if ru not in redirect_uris:
                            raise OAuthError('invalid_request',
                                             'Redirect URI not in json document pointed by sector_identifier_uri')
                except OAuthError:
                    raise
                except BaseException as e:
                    raise OAuthError('invalid_request',
                                     'Error fetching/parsing sector_identifier_uri at %s: %s' %
                                     (self.request_parameters.sector_identifier_uri, str(e)))
                pairwise_key = urlparse(self.request_parameters.sector_identifier_uri).hostname
            else:
                for ru in self.request_parameters.redirect_uris:
                    hostname = urlparse(ru).hostname
                    if pairwise_key and pairwise_key != hostname:
                        raise OAuthError('invalid_request', 'In case that redirect_uris do not share the same host, '
                                                            'sector_identifier_uri parameter is required')
                    pairwise_key = hostname

            if 'pairwise' in self.request_parameters.subject_type:
                pairwise_key = hashlib.sha256((pairwise_key + settings.SECRET_KEY).encode('utf-8')).hexdigest()
            else:
                pairwise_key = None

            client_id = secrets.token_urlsafe(32)
            client_secret = secrets.token_urlsafe(32)

            client_data = json.loads(request.body.decode('utf-8'))

            if 'jwks_uri' in client_data:
                jwks = requests.get(client_data['jwks_uri']).json()
            elif 'jwks' in client_data:
                jwks = client_data['jwks']
            else:
                jwks = {'keys': []}
            jwks = json.dumps(jwks, indent=True)
            print("registered jwks", jwks)

            client = OpenIDClient.objects.create(
                client_id=client_id,
                redirect_uris='\n'.join(self.request_parameters.redirect_uris),
                client_auth_type=self.get_auth_type(self.request_parameters.token_endpoint_auth_method),
                client_name=self.request_parameters.client_name,
                sub_hash = pairwise_key,
                client_registration_data=client_data,
                jwks=jwks
            )
            client.set_client_secret(client_secret)
            client.save()

            resp = self.make_registration_response(request, client, client_secret)

            return JsonResponse(resp, status=201)

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })

    @staticmethod
    def make_registration_response(request, client, client_secret):
        resp = {}
        resp.update(client.client_registration_data)
        resp.update({
            "client_id": client.client_id,
            "client_secret": client_secret,
            "client_secret_expires_at": 0,
        })
        if request.openid_access_token:
            user = request.openid_access_token.user
        else:
            user = User.objects.get(username='admin')
        registration_access_token, registration_access_db_token = \
            OpenIDToken.create_token(client, OpenIDToken.TOKEN_TYPE_CLIENT_CONFIGURATION_TOKEN,
                                     {}, OpenIDToken.INFINITE_TTL, user)
        resp.update({
            'registration_access_token': registration_access_token,
            'registration_client_uri': request.build_absolute_uri(
                reverse('openid_connect_op:client_configuration', kwargs=dict(client_id=client.client_id)))
        })
        return resp

    @staticmethod
    def get_auth_type(token_endpoint_auth_method):
        return {
            "client_secret_basic" : OpenIDClient.CLIENT_AUTH_TYPE_BASIC,
            "client_secret_post" : OpenIDClient.CLIENT_AUTH_TYPE_POST,
            "private_key_jwt": OpenIDClient.CLIENT_AUTH_TYPE_PRIVATE_KEY_JWT,
            "client_secret_jwt": OpenIDClient.CLIENT_AUTH_TYPE_SECRET_JWT
        }[token_endpoint_auth_method or "client_secret_basic"]
