import pytest
from django.contrib.auth.models import User
from django.utils import timezone

from openid_connect_op.models import OpenIDClient, OpenIDAgreement, OpenIDUserAgreement


@pytest.mark.django_db
class TestAgreements:

    def test_obligatory_agreements(self):
        client_config = OpenIDClient.objects.create(redirect_uris='http://my-site.com/auth/complete')
        agr1 = OpenIDAgreement.objects.create(client=client_config, text='Lorem ipsum', obligatory=True)
        agr2 = OpenIDAgreement.objects.create(client=client_config, text='Dolor sit amet', obligatory=True)

        u = User.objects.create(username='aa@vscht.cz')
        assert not client_config.has_user_agreement(u)

        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == {agr1, agr2}

        OpenIDUserAgreement.objects.create(agreement=agr1, user=u, agreed_on=timezone.now())

        assert not client_config.has_user_agreement(u)
        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == {agr2}

        OpenIDUserAgreement.objects.create(agreement=agr2, user=u, agreed_on=timezone.now())

        assert client_config.has_user_agreement(u)
        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == set()

    def test_optional_agreements(self):
        client_config = OpenIDClient.objects.create(redirect_uris='http://my-site.com/auth/complete')
        agr1 = OpenIDAgreement.objects.create(client=client_config, text='Lorem ipsum', obligatory=False)
        agr2 = OpenIDAgreement.objects.create(client=client_config, text='Dolor sit amet', obligatory=False)

        u = User.objects.create(username='aa@vscht.cz')
        assert client_config.has_user_agreement(u)

        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == {agr1, agr2}

        OpenIDUserAgreement.objects.create(agreement=agr1, user=u, agreed_on=timezone.now())

        assert client_config.has_user_agreement(u)
        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == {agr2}

        OpenIDUserAgreement.objects.create(agreement=agr2, user=u, agreed_on=timezone.now())

        assert client_config.has_user_agreement(u)
        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == set()

    def test_auto_approved_agreements(self):
        client_config = OpenIDClient.objects.create(redirect_uris='http://my-site.com/auth/complete')
        agr1 = OpenIDAgreement.objects.create(client=client_config, text='Lorem ipsum', obligatory=True,
                                              username_auto_agreement_regexp='^.*@vscht.cz$')

        u = User.objects.create(username='aa@vscht.cz')
        assert client_config.has_user_agreement(u)

        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == set()

    def test_auto_approved_agreements2(self):
        client_config = OpenIDClient.objects.create(redirect_uris='http://my-site.com/auth/complete')
        agr1 = OpenIDAgreement.objects.create(client=client_config, text='Lorem ipsum', obligatory=True,
                                              username_auto_agreement_regexp='^.*@vscht.cz$')

        u = User.objects.create(username='aa@gmail.com')
        assert not client_config.has_user_agreement(u)

        unsigned_agreements = set(client_config.get_unsigned_agreements(u))
        assert unsigned_agreements == {agr1}
