import requests
from django.conf import settings
from django.contrib.auth.models import Group
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthUnreachableProvider


class OpenIdConnectBackend(OpenIdConnectAuth):
    name = 'test'
    AUTHORIZATION_URL = settings.OPENID_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = settings.OPENID_ACCESS_TOKEN_URL
    USER_DETAIL_URL = settings.OPENID_USER_DETAIL_URL
    REDIRECT_STATE = True
    DEFAULT_SCOPE = [
        'http://djangoproject.com/openid',
        'openid',
        'profile',
        'email'
    ]
    ID_KEY = 'http://djangoproject.com/openid#username'
    OIDC_ENDPOINT = settings.OPENID_OIDC_URL

    def get_user_details(self, response):
        """Return user details from Cis-Login account"""
        resp = super().get_user_details(response['details'])
        group_names = response['details'].get('http://djangoproject.com/openid#groups', [])
        group_ids = [
            Group.objects.get_or_create(name=group_name)[0].id for group_name in group_names
        ]

        resp.update({
            'is_django_admin': response['details'].get('http://djangoproject.com/openid#is_admin'),
            'is_django_staff': response['details'].get('http://djangoproject.com/openid#is_staff'),
            'username': response['details'].get(self.ID_KEY),
            'groups': group_ids,
        })
        return resp

    def user_data(self, access_token, *args, **kwargs):
        resp = requests.get(
            CisLoginBackend.USER_DETAIL_URL + "self",
            {
                'client_id': self.setting('KEY')
            },
            headers={
                'Authorization': 'Bearer %s' % access_token
            })
        if resp.status_code != 200:
            raise AuthUnreachableProvider(self, 'Could not contact cis-login server to get user details')
        data = resp.json()
        return {'details': data}

    def get_user_id(self, details, response):
        return response['details'][self.ID_KEY]

