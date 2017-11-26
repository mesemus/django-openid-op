import time

import pytest

from openid_connect_op.utils.crypto import CryptoTools

key = b'1234567890ABCDEF'


def test_crypt_decrypt():
    plaintext = b'Lorem ipsum dolor sit amet'
    crypto_text = CryptoTools.encrypt(plaintext, key=key)
    decrypted = CryptoTools.decrypt(crypto_text, key=key)
    assert decrypted == plaintext


def test_crypt_decrypt_timing():
    plaintext = b'Lorem ipsum dolor sit amet'
    crypto_text = CryptoTools.encrypt(plaintext, key=key, ttl=1)
    decrypted = CryptoTools.decrypt(crypto_text, key=key)
    assert decrypted == plaintext

    time.sleep(1)
    with pytest.raises(AttributeError) as e:
        CryptoTools.decrypt(crypto_text, key=key)
    assert 'The message has expired' == str(e.value)


def test_prefixes():
    plaintext = b'Lorem ipsum dolor sit amet'
    crypto_text = CryptoTools.encrypt(plaintext, key=key, prefix=b'abc')
    decrypted = CryptoTools.decrypt(crypto_text, key=key, expected_prefix=b'abc')
    assert decrypted == plaintext

    with pytest.raises(AttributeError) as e:
        CryptoTools.decrypt(crypto_text, key=key, expected_prefix=b'def')
    assert 'Expecting prefix b\'def\', got b\'abc\'' == str(e.value)
