from openid_connect_op.models import OpenIDClient


class TestRedirectURIMatching:
    def test_exact_match(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete')

    def test_exact_match_two_uris(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete\n  http://my-site1.com/auth/complete')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete')
        assert client_config.check_redirect_url('http://my-site1.com/auth/complete')

    def test_non_match(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete')
        assert not client_config.check_redirect_url('http://my-site.org/auth/complete')
        assert not client_config.check_redirect_url('http://my-site.com:80/auth/complete')
        assert not client_config.check_redirect_url('http://my-site.com:8000/auth/complete')

    def test_match_with_param_with_value(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete?a=2')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete?a=2')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete?a=3')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete?a')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete')

    def test_match_with_param(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete?a')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete?a=2')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete?a=3')
        assert client_config.check_redirect_url('http://my-site.com/auth/complete?a')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete')

    def test_match_without_defined_param(self):
        client_config = OpenIDClient(redirect_uris='http://my-site.com/auth/complete')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete?a=3')
        assert not client_config.check_redirect_url('http://my-site.com/auth/complete?a')

