import pytest
import random

from cryptolib.oracles import PaddingOracle, SequentialOracle
from cryptolib.pipes import CBCEncrypt, AddIV
from cryptolib.utils.padding import pkcs7
random.seed(1)


def test_PaddingOracle():
    # Probably deserves more testing but some of it should be covered by testing of is_valid_pkcs function
    key = random.randbytes(32)
    iv_seed = 1
    proper_pad = SequentialOracle([
        lambda message: pkcs7(message, 16),
        AddIV(seed=iv_seed),
        CBCEncrypt('aes', key)
    ])
    oracle = PaddingOracle('cbc', 'aes', key)
    for b in range(1, 256):
        # An oracle that messes with the last byte of padding before encrypting
        improper_pad = SequentialOracle([
            lambda message: pkcs7(message, 16),
            AddIV(seed=iv_seed),
            lambda message: message[:-1] + bytes([b ^ message[-1]]),
            CBCEncrypt('aes', key),
        ])
        message = random.randbytes(random.randint(0, 30))
        assert oracle(proper_pad(message)) == b'good'
        assert oracle(improper_pad(message)) == b'bad'
