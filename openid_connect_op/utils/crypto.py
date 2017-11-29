import base64
import hmac
import struct
import time

import zlib
from Cryptodome.Cipher import AES


class CryptoTools:

    @staticmethod
    def encrypt(message, ttl=None, not_valid_before=None, key=None, prefix=b'', zlib_dict=b''):
        """
        Encrypts a message and puts in timestamp

        :param message:     an instance of bytes
        :param ttl:         time to live in seconds
        :param not_valid_before:  integer, number of seconds since epoch as given by time.time()
        :param key:         an array of 16 bytes, if not set use settings.OPENID_CONNECT_OP_AES_KEY
        :param prefix:      add this prefix to the message before encryption, during decrypt the message will be checked for it
        :return:            a timestamped, encrypted and signed message
        """
        if b':' in prefix:
            raise AttributeError('Prefix must not contain character :')

        if ttl is not None:
            if not_valid_before is None:
                not_valid_before = int(time.time())

        if ttl is None:
            not_valid_after = 2 ** 64 - 1
        else:
            not_valid_after = not_valid_before + ttl

        not_valid_after  = struct.pack('>Q', not_valid_after)

        message = not_valid_after + prefix + b':' + message

        co = zlib.compressobj(level=9, wbits=-9, zdict=zlib_dict)
        message = co.compress(message) + co.flush()

        if key is None:
            raise AttributeError('Key can not be None')
        assert len(key) == 16

        cipher = AES.new(key, AES.MODE_GCM)
        cipher_text, tag = cipher.encrypt_and_digest(message)
        encrypted_message = b''.join([cipher.nonce, tag, cipher_text])
        ret = base64.urlsafe_b64encode(encrypted_message)
        while ret[-1] == ord(b'='):
            ret = ret[:-1]
        return ret

    @staticmethod
    def decrypt(message, check_ttl=True, key=None, expected_prefix=b'', zlib_dict=b''):
        """
        Decrypts a message and checks that it has not yet expired

        :param message:     the encrypted message
        :param check_ttl:   if true, check its ttl, if false, ignore ttl at all
        :param key:         an array of 16 bytes, if not set use settings.OPENID_CONNECT_OP_AES_KEY
        :return:
        :param expected_prefix: the message will be checked against this prefix and if it does not match, an AttributeError will be raised
        """
        if key is None:
            raise AttributeError('Key can not be None')

        if len(message) % 4 == 2:
            message += b'=='
        elif len(message) % 4 == 3:
            message += b'='
        encrypted_message = base64.urlsafe_b64decode(message)
        # nonce and tag are always 16 bytes long
        nonce, tag, cipher_text = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        message = cipher.decrypt_and_verify(cipher_text, tag)

        do = zlib.decompressobj(wbits=-9, zdict=zlib_dict)
        message = do.decompress(message) + do.flush()

        not_valid_after = message[:8]
        message = message[8:]

        if check_ttl:
            not_valid_after  = struct.unpack('>Q', not_valid_after)[0]
            current_time = time.time()
            if current_time > not_valid_after:
                raise AttributeError('The message has expired')

        prefix, message = message.split(b':', maxsplit=1)
        if not hmac.compare_digest(prefix, expected_prefix):
            # use hmac to prevent timing attacks
            raise AttributeError('Expecting prefix %s, got %s' % (expected_prefix, prefix))

        return message
