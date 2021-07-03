import pytest
import random

from Crypto.Cipher import AES
from cryptolib.oracles import SequentialOracle
from cryptolib.pipes import CBCEncrypt

rng = random.Random(1)


def test_CBCEncrypt():

    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        iv = rng.randbytes(AES.block_size)

        reference_cipher = AES.new(key, AES.MODE_CBC, iv)

        # A CBC pipe requires an oracle to give it an IV.
        oracle = CBCEncrypt('aes', key)

        message = random.randbytes(48)
        enc_message = oracle(iv + message)[AES.block_size:]
        expected_out = reference_cipher.encrypt(message)
        assert enc_message == expected_out

    # Should fail to encrypt if the block size is wrong and if an empty message is passed.
    for n in range(0, 16):
        try:
            oracle(b'a'*n)
        except ValueError:
            assert True
        else:
            assert False, n
    for n in range(17, 32):
        try:
            oracle(b'a'*n)
        except ValueError:
            assert True
        else:
            assert False, n
