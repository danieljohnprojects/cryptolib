import pytest
import random

from Crypto.Cipher import AES
from cryptolib.oracles import SequentialOracle
from cryptolib.pipes import BCDecrypt

random.seed(1)


def test_ECB_encryption():
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = random.randbytes(key_len)

        reference_cipher = AES.new(key, AES.MODE_ECB)

        pipe = BCDecrypt(
            'ecb',
            'aes',
            key=key
        )
        oracle = SequentialOracle([pipe])

        message = random.randbytes(48)
        dec_message = oracle.divine(message)
        expected_out = reference_cipher.decrypt(message)
        assert dec_message == expected_out


def test_CBC_encryption():
    key_lens = [16, 24, 32]
    for key_len in key_lens:
        key = random.randbytes(key_len)
        pipe = BCDecrypt(
            'cbc',
            'aes',
            key=key,
            iv=bytes(16)
        )
        for _ in range(10):
            iv = random.randbytes(16)
            pipe.set_iv(iv)
            reference_cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            oracle = SequentialOracle([pipe])

            message = random.randbytes(48)
            dec_message = oracle.divine(message)
            expected_out = reference_cipher.decrypt(message)
            assert dec_message == expected_out
