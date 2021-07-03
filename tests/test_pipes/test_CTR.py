import pytest
import random

from Crypto.Cipher import AES
from cryptolib.pipes import CTR


def test_CTR():
    rng = random.Random(1)
    nonce_size = 8

    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        nonce = rng.randbytes(nonce_size)

        reference_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

        # A CBC pipe requires an oracle to give it an IV.
        oracle = CTR('aes', key, nonce_size=nonce_size, ctr_endianness='big')

        message = random.randbytes(random.randint(0, 200))
        enc_message = oracle(nonce + message)
        expected_out = reference_cipher.encrypt(message)
        assert enc_message == expected_out

