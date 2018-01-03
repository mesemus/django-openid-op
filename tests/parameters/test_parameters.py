import pytest

from openid_connect_op.utils.params import Parameters, ParameterType
try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

import jwcrypto.jwk as jwk


class Params(Parameters):
    parameter_definitions = (
        ('a', Parameters.REQUIRED),
        ('b', Parameters.OPTIONAL),
        ('c', ParameterType(required=False, container_type=set)),
        ('d', ParameterType(required=False, container_type=list)),
        ('e', ParameterType(required=False, container_type=set, allowed_values=('a', 'b', 'c')))
    )


def test_parameter_parsing():
    p = Params({
        'a': 'abc',
        'b': 'def',
        'c': 'a ba',
        'd': 'ba a'
    }).check_errors()
    assert p.a == 'abc'
    assert p.b == 'def'
    assert p.c == {'a', 'ba'}
    assert p.d == ['ba', 'a']


def test_required_parameter():
    with pytest.raises(AttributeError) as e:
        Params({}).check_errors()
    assert str(e.value) == 'Required parameter with name "a" is not present'


def test_allowed_values():
    p = Params({
        'a': '123',
        'e': 'a c b'
    }).check_errors()
    assert p.a == '123'
    assert p.e == {'a', 'b', 'c'}

    with pytest.raises(AttributeError) as e:
        Params({
            'a': '123',
            'e': 'a c b d'
        }).check_errors()
    assert str(e.value) == 'Value "d" is not allowed for parameter e. Allowed values are "a", "b", "c"'


def test_pack_unpack():
    p = Params({
        'a': 'abc,',
        'b': 'def',
        'd': 'ba a'
    }).check_errors()
    key = jwk.JWK.generate(kty='oct', alg='AES', size=16*8, kid=secrets.token_urlsafe(32))
    assert isinstance(p.d, list)
    packed = p.pack(True, prefix=b'TOK', key=key)
    unpacked_p = Params.unpack(packed, prefix=b'TOK', key=key)
    assert p == unpacked_p
    assert str(p) == str(unpacked_p)
