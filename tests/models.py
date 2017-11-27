from openid_connect_op.models import AbstractOpenIDClient, AbstractTokenStore


class ClientConfig(AbstractOpenIDClient):
    pass


class TokenStore(AbstractTokenStore):
    pass