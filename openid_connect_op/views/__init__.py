import json
from urllib.parse import urlencode

from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.utils.functional import cached_property

from openid_connect_op.views.errors import OAuthError
from openid_connect_op.views.parameters import TokenParameters


class OAuthRequestMixin:

    request_parameters = None
    use_redirect_uri = True
    attribute_parsing_error = 'invalid_request_uri'

    def oauth_send_answer(self, request, response_params):
        actual_params = {}
        actual_params.update(response_params)
        if self.request_parameters:
            redirect_uri = self.request_parameters.redirect_uri
            if hasattr(self.request_parameters, 'state') and self.request_parameters.state:
                actual_params['state'] = self.request_parameters.state
        else:
            redirect_uri = request.GET.get('redirect_uri', None) or request.POST.get('redirect_uri', None)

        if not redirect_uri or not self.use_redirect_uri:
            return JsonResponse(actual_params, status=400 if 'error' in response_params else 200)

        if '?' in redirect_uri:
            redirect_uri += '&'
        else:
            redirect_uri += '?'
        redirect_uri += urlencode(actual_params)
        return HttpResponseRedirect(redirect_uri)

    def parse_request_parameters(self, request, parameters_class):
        try:
            if request.method == 'GET':
                params = {k:v for k, v in request.GET.items()}
            else:
                params = {}
                if request.GET:
                    params.update({k:v for k, v in request.GET.items()})
                if request.POST:
                    params.update({k:v for k, v in request.POST.items()})
                if request.content_type == 'application/json':
                    params.update(json.loads(request.body.decode('utf-8')))

            # noinspection PyAttributeOutsideInit
            self.request_parameters = parameters_class(params)
        except AttributeError as e:
            raise OAuthError(error=self.attribute_parsing_error, error_description=str(e))

