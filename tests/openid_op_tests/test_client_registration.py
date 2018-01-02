import hashlib
import json

import pytest
import re
from django.contrib.auth.models import User
from django.core.management import call_command

from openid_connect_op.models import OpenIDToken, OpenIDClient


@pytest.mark.django_db
class TestClientRegistrationRequest:
    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    def test_client_registration_bad_token(self, client):
        resp = client.post(
            '/openid/register',
            json.dumps({}),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth('abc'))
        assert resp.status_code == 403

    def test_client_registration_bad_token2(self, client, openid_client, user):
        token = OpenIDToken.create_token(openid_client, OpenIDToken.TOKEN_TYPE_ACCESS_BEARER_TOKEN,
                                         {}, 1e9, user)[0]
        resp = client.post(
            '/openid/register',
            json.dumps({}),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth(token))

        assert resp.status_code == 403

    def test_client_registration_no_redirect_uri(self, client, openid_client, user):
        token = OpenIDToken.create_token(openid_client, OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION,
                                         {}, 1e9, user)[0]
        resp = client.post(
            '/openid/register',
            json.dumps({}),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth(token))

        assert resp.status_code == 400
        assert json.loads(resp.content.decode('utf-8')) == {
            'error': 'invalid_request',
            'error_description': 'Required parameter with name "redirect_uris" is not present'
        }

    def test_client_registration_ok(self, client, openid_client, user):
        token = OpenIDToken.create_token(openid_client, OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION,
                                         {}, 1e9, user)[0]
        resp = client.post(
            '/openid/register',
            json.dumps({
                'redirect_uris': [
                    'http://test.org/auth/complete'
                ],
                'another': 1
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth(token))

        assert resp.status_code == 201
        content = json.loads(resp.content.decode('utf-8'))
        assert 'client_id' in content
        assert 'client_secret' in content
        client_id = content.pop('client_id')
        client_secret = content.pop('client_secret')
        registration_access_token = content.pop('registration_access_token')
        assert len(registration_access_token) > 32
        registration_client_uri = content.pop('registration_client_uri')
        assert registration_client_uri.startswith('http://testserver/openid/client_configuration/')
        assert content == {
            'another': 1,
            'client_secret_expires_at': 0,
            'redirect_uris': ['http://test.org/auth/complete']
        }

        client = OpenIDClient.objects.get(client_id=client_id)
        assert client.check_client_secret(client_secret)

    def test_client_registration_pairwise(self, client, openid_client, user):
        token = OpenIDToken.create_token(openid_client, OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION,
                                         {}, 1e9, user)[0]
        resp = client.post(
            '/openid/register',
            json.dumps({
                'redirect_uris': [
                    'http://test.org/auth/complete'
                ],
                'subject_type': ['pairwise'],
                'another': 1
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth(token))

        assert resp.status_code == 201
        content = json.loads(resp.content.decode('utf-8'))
        assert 'client_id' in content
        assert 'client_secret' in content
        client_id = content.pop('client_id')
        client_secret = content.pop('client_secret')
        registration_access_token = content.pop('registration_access_token')
        assert len(registration_access_token) > 32
        registration_client_uri = content.pop('registration_client_uri')
        assert registration_client_uri.startswith('http://testserver/openid/client_configuration/')
        assert content == {
            'another': 1,
            'client_secret_expires_at': 0,
            'redirect_uris': ['http://test.org/auth/complete'],
            'subject_type': ['pairwise'],
        }

        client = OpenIDClient.objects.get(client_id=client_id)
        assert client.check_client_secret(client_secret)

        from django.conf import settings
        assert client.sub_hash == hashlib.sha256(('test.org' + settings.SECRET_KEY).encode('utf-8')).hexdigest()

    def test_client_configuration_service(self, client, openid_client, user):
        token = OpenIDToken.create_token(openid_client, OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION,
                                         {}, 1e9, user)[0]
        resp = client.post(
            '/openid/register',
            json.dumps({
                'redirect_uris': [
                    'http://test.org/auth/complete'
                ],
                'another': 1
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=self.format_auth(token))

        content = json.loads(resp.content.decode('utf-8'))
        registration_access_token = content.pop('registration_access_token')
        registration_client_uri = content.pop('registration_client_uri')
        client_id = content.pop('client_id')

        resp = client.get(registration_client_uri, HTTP_AUTHORIZATION=self.format_auth(registration_access_token))
        assert resp.status_code == 200
        content = json.loads(resp.content.decode('utf-8'))

        assert 'client_id' in content
        assert 'client_secret' in content
        new_client_id = content.pop('client_id')
        content.pop('client_secret')
        assert new_client_id == client_id
        new_registration_access_token = content.pop('registration_access_token')
        assert len(new_registration_access_token) > 32
        new_registration_client_uri = content.pop('registration_client_uri')
        assert new_registration_client_uri == registration_client_uri
        assert registration_client_uri.startswith('http://testserver/openid/client_configuration/')
        assert content == {
            'another': 1,
            'client_secret_expires_at': 0,
            'redirect_uris': ['http://test.org/auth/complete']
        }


    @pytest.fixture()
    def openid_client(self):
        return OpenIDClient.objects.create(
            client_id='1',
            client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_BASIC,
        )

    @pytest.fixture
    def user(self):
        return User.objects.create(username='a')

    def format_auth(self, token):
        return 'Bearer ' + token
