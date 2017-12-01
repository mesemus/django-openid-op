from urllib.parse import splitquery

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.http.response import HttpResponseBadRequest, HttpResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from openid_connect_op.models import OpenIDClient, OpenIDKey
from openid_connect_op.signals import before_user_consent
from openid_connect_op.views.parameters import AuthenticationParameters
from . import OAuthRequestMixin
from .errors import OAuthError


class AuthenticationRequestView(OAuthRequestMixin, View):
    # noinspection PyAttributeOutsideInit
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        if request.method not in ('GET', 'POST'):
            return HttpResponseBadRequest('Only GET or POST are supported on OpenID endpoint')

        try:
            self.unpack_auth_parameters(request)

            self.validate_max_age()

            client = self._get_client_or_raise_exception()

            if self.should_login(request):
                return self.authenticate(request)

            should_sign_consent = self.should_request_user_consent(request, client)

            signal_responses = before_user_consent.send(type(client),
                                             openid_client=client,
                                             user=request.user,
                                             consent_already_signed=not should_sign_consent)
            for resp in signal_responses:
                if isinstance(resp[1], HttpResponse):
                    return resp[1]

            if should_sign_consent:
                return self.request_user_consent(request, client)

            if 'code' in self.request_parameters.response_type:
                self.request_parameters.username = request.user.username
                return self.oauth_send_answer(request, {
                    'code': self.request_parameters.pack(ttl=60, prefix=b'AUTH',
                                                         key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY)
                                                         )
                })
            else:
                raise OAuthError(error='parameter_not_supported',
                                 error_description='Only "code" value of the "response_type" '
                                                   'is supported by this server')

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })

    def should_request_user_consent(self, request, client):
        return not client.has_user_agreement(request.user) or 'consent' in self.request_parameters.prompt

    def should_login(self, request):
        if request.user.is_anonymous or 'login' in self.request_parameters.prompt:
            if 'none' in self.request_parameters.prompt:
                raise OAuthError(error='login_required',
                                 error_description='No prompt requested but user is not logged in')
            return True
        return False

    def _get_client_or_raise_exception(self):
        try:
            client = OpenIDClient.objects.get(client_id=self.request_parameters.client_id)
        except OpenIDClient.DoesNotExist:
            raise OAuthError(error='unauthorized_client',
                             error_description='The client is unauthorized to get authentication token')
        if not client.check_redirect_url(self.request_parameters.redirect_uri):
            raise OAuthError(error='unauthorized_client',
                             error_description='The client is unauthorized to get authentication token '
                                               'as the redirect_uri does not match')
        return client

    def validate_max_age(self):
        if self.request_parameters.max_age:
            raise OAuthError(error='parameter_not_supported',
                             error_description='Parameter max_age is currently not supported by the server')

    def unpack_auth_parameters(self, request):
        try:
            if 'authp' in request.GET:
                self.request_parameters = AuthenticationParameters.unpack(
                    request.GET['authp'].encode('ASCII'), key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY))
            else:
                return self.parse_request_parameters(request, AuthenticationParameters)
        except AttributeError as e:
            raise OAuthError(error='invalid_request_uri', error_description=str(e))

    def authenticate(self, request):
        # if user is already logged in, a re-logging was requested, so forget the user
        if not request.user.is_anonymous:
            logout(request)

        this_url_with_encrypted_params = self.get_this_url_with_params(request)
        return HttpResponseRedirect(
            settings.LOGIN_URL + '?' + urlencode(
                {
                    'next': this_url_with_encrypted_params
                }
            )
        )

    def request_user_consent(self, request, client):
        this_url_with_encrypted_params = self.get_this_url_with_params(request)
        return HttpResponseRedirect(
            reverse(settings.OPENID_USER_CONSENT_VIEW, kwargs=dict(client_id=client.id)) + '?' + urlencode(
                {
                    'next': this_url_with_encrypted_params
                }
            )
        )

    def get_this_url_with_params(self, request):
        server, query = splitquery(request.build_absolute_uri())
        params = {
            'authp': self.request_parameters.pack(key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY))
        }
        return server + '?' + urlencode(params)
