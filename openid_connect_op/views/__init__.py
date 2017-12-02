import json
from urllib.parse import urlencode

from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.cache import add_never_cache_headers
from django.utils.functional import cached_property

from openid_connect_op.views.errors import OAuthError
from openid_connect_op.views.parameters import TokenParameters


class OAuthRequestMixin:
    request_parameters = None
    use_redirect_uri = True
    attribute_parsing_error = 'invalid_request'

    def oauth_send_answer(self, request, response_params):
        actual_params = {}
        actual_params.update(response_params)
        redirect_uri = getattr(self.request_parameters, 'redirect_uri', None) or \
                       request.GET.get('redirect_uri', None) or \
                       request.POST.get('redirect_uri', None)
        if hasattr(self.request_parameters, 'state') and self.request_parameters.state:
            actual_params['state'] = self.request_parameters.state

        if hasattr(self.request_parameters, 'response_mode') and 'form_post' in self.request_parameters.response_mode:
            resp = render(request, 'django-open-id/form_post_response_mode.html', {
                'params': actual_params,
                'redirect_uri': redirect_uri
            })
            add_never_cache_headers(resp)
            return resp

        if not redirect_uri or not self.use_redirect_uri:
            status = 200
            if 'error' in response_params:
                if response_params['error'] == 'unauthorized_client':
                    status = 403
                else:
                    status = 400
            return JsonResponse(actual_params, status=status)

        if '?' in redirect_uri:
            redirect_uri += '&'
        else:
            redirect_uri += '?'
        redirect_uri += urlencode(actual_params)
        return HttpResponseRedirect(redirect_uri)

    def parse_request_parameters(self, request, parameters_class):
        try:
            if request.method == 'GET':
                params = {k: v for k, v in request.GET.items()}
            else:
                params = {}
                if request.GET:
                    params.update({k: v for k, v in request.GET.items()})
                if request.POST:
                    params.update({k: v for k, v in request.POST.items()})
                if request.content_type == 'application/json':
                    params.update(json.loads(request.body.decode('utf-8')))

            # noinspection PyAttributeOutsideInit
            self.request_parameters = parameters_class(params)
        except AttributeError as e:
            raise OAuthError(error=self.attribute_parsing_error, error_description=str(e))
