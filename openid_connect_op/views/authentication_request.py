from urllib.parse import splitquery

from django.apps import apps
from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.http.response import HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.utils.http import urlencode
from django.views import View

from ..utils.params import ParameterType, Parameters


class AuthenticationParameters(Parameters):
    parameter_definitions = {
        'redirect_uri': Parameters.REQUIRED,
        'client_id': Parameters.REQUIRED,
        'scope': ParameterType(required=True, container_type=set),
        'response_type': ParameterType(required=True, container_type=set, allowed_values={'code', 'token', 'id_token'}),

        'state': Parameters.OPTIONAL,
        # currently not used at all
        # 'nonce': Parameters.OPTIONAL,
        'max_age': Parameters.OPTIONAL,
        # currently not used at all
        # 'id_token_hint': Parameters.OPTIONAL,
        # 'login_hint': Parameters.OPTIONAL,
        'response_mode': ParameterType(required=False, container_type=set, allowed_values={'query', 'fragment'}),
        # currently not used at all
        # 'display': ParameterType(required=False, container_type=set,
        #                          allowed_values={'page', 'popup', 'touch', 'wap'}),
        'prompt': ParameterType(required=False, container_type=set,
                                allowed_values={'none', 'login', 'consent', 'select_account'}),
        # currently not used at all
        # 'ui_locales': ParameterType(required=False, container_type=list),
        # 'acr_values': ParameterType(required=False, container_type=list),
    }

    def __init__(self, params):

        super().__init__(params)


class OAuthError(BaseException):
    def __init__(self, error=None, error_description=None):
        self.error = error
        self.error_description = error_description


class AuthenticationRequestView(View):
    # noinspection PyAttributeOutsideInit
    def dispatch(self, request, *args, **kwargs):
        if request.method not in ('GET', 'POST'):
            return HttpResponseBadRequest('Only GET or POST are supported on OpenID endpoint')

        self.authentication_parameters = None

        try:
            self.unpack_auth_parameters(request)

            self.check_max_age()

            client = self._get_client_or_raise_exception()

            if self.should_login(request):
                return self.authenticate(request)

            if self.should_request_user_consent(request, client):
                return self.request_user_consent(request, client)

            if 'code' in self.authentication_parameters.response_type:
                return self.oauth_send_answer(request, {
                    'code': self.authentication_parameters.pack(ttl=60, prefix=b'AUTH')
                })
            else:
                raise OAuthError(error='parameter_not_supported',
                                 error_description='Only "code" value of the "response_type" is supported by this server')

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })

    def should_request_user_consent(self, request, client):
        return not client.has_user_approval(request.user) or 'consent' in self.authentication_parameters.prompt

    def should_login(self, request):
        if request.user.is_anonymous or 'login' in self.authentication_parameters.prompt:
            if 'none' in self.authentication_parameters.prompt:
                raise OAuthError(error='login_required',
                                 error_description='No prompt requested but user is not logged in')
            return True
        return False

    def _get_client_or_raise_exception(self):
        openid_client_model = apps.get_model(*settings.OPENID_CLIENT_MODEL.split('.'))
        try:
            client = openid_client_model.objects.get(client_id=self.authentication_parameters.client_id)
        except openid_client_model.DoesNotExist:
            raise OAuthError(error='unauthorized_client',
                             error_description='The client is unauthorized to get authentication token')
        if not client.check_redirect_url(self.authentication_parameters.redirect_uri):
            raise OAuthError(error='unauthorized_client',
                             error_description='The client is unauthorized to get authentication token '
                                               'as the redirect_uri does not match')
        return client

    def check_max_age(self):
        if self.authentication_parameters.max_age:
            raise OAuthError(error='parameter_not_supported',
                             error_description='Parameter max_age is currently not supported by the server')

    def unpack_auth_parameters(self, request):
        try:
            if 'authp' in request.GET:
                self.authentication_parameters = AuthenticationParameters.unpack(
                    request.GET['authp'].encode('ASCII'))
            else:
                if request.method == 'GET':
                    params = request.GET
                else:
                    params = request.POST
                self.authentication_parameters = AuthenticationParameters(params)
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
            'authp': self.authentication_parameters.pack()
        }
        return server + '?' + urlencode(params)

    def oauth_send_answer(self, request, response_params):
        actual_params = {}
        actual_params.update(response_params)
        if self.authentication_parameters:
            if self.authentication_parameters.state:
                actual_params['state'] = self.authentication_parameters.state
            redirect_uri = self.authentication_parameters.redirect_uri
        else:
            redirect_uri = request.GET.get('redirect_uri', None) or request.POST.get('redirect_uri', None)

        if not redirect_uri:
            return JsonResponse(actual_params, status=400)

        if '?' in redirect_uri:
            redirect_uri += '&'
        else:
            redirect_uri += '?'
        redirect_uri += urlencode(actual_params)
        return HttpResponseRedirect(redirect_uri)
