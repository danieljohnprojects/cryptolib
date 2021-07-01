import pytest
import random

from Crypto.Cipher import AES
from cryptolib.pipes import ECBEncrypt

random.seed(1)


def test_ECBEncrypt():

    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = random.randbytes(key_len)

        reference_cipher = AES.new(key, AES.MODE_ECB)

        pipe = ECBEncrypt('aes', key)

        message = random.randbytes(48)
        enc_message = pipe(message)
        expected_out = reference_cipher.encrypt(message)
        assert enc_message == expected_out

    # Encrypting an empty message should give an empty message back.
    assert pipe(b'') == b''

    # Should fail to encrypt if the block size is wrong.
    for n in range(1, 16):
        try:
            pipe(b'a'*n)
        except ValueError:
            assert True
        else:
            assert False, n
