import pytest
import random

from Crypto.Cipher import AES
from cryptolib.oracles import SequentialOracle
from cryptolib.pipes import CBCEncrypt

random.seed(1)


def test_CBCEncrypt():

    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = random.randbytes(key_len)
        iv = random.randbytes(16)

        reference_cipher = AES.new(key, AES.MODE_CBC, iv)

        # A CBC pipe requires an oracle to give it an IV.
        oracle = SequentialOracle([CBCEncrypt('aes', key)])
        oracle.iv = iv

        message = random.randbytes(48)
        enc_message = oracle(message)
        expected_out = reference_cipher.encrypt(message)
        assert enc_message == expected_out

    # Encrypting an empty message should give an empty message back.
    assert oracle(b'') == b''

    # Should fail to encrypt if the block size is wrong.
    for n in range(1, 16):
        try:
            oracle(b'a'*n)
        except ValueError:
            assert True
        else:
            assert False, n
