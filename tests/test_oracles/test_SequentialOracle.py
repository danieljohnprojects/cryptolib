import pytest
import random

from Crypto.Cipher import AES

from cryptolib.oracles import SequentialOracle
from cryptolib.pipes import CBCEncrypt, CBCDecrypt, AddIV
from cryptolib.utils.padding import pkcs7, strip_pkcs7

random.seed(1)

def test_SequentialOracle():
    # Constant oracle
    oracle = SequentialOracle([
        lambda message: b''
    ])
    for _ in range(5):
        assert(oracle(random.randbytes(random.randint(10, 20))) == b'')

    # Prefix oracle
    prefix = random.randbytes(6)
    oracle = SequentialOracle([
        lambda message: prefix + message
    ])
    for _ in range(5):
        message = random.randbytes(random.randint(10, 20))
        assert(oracle(message) == prefix + message)

    # CBC Encryption oracle
    iv_seed=1
    key = random.randbytes(16)
    oracle = SequentialOracle([
        lambda message: pkcs7(message, AES.block_size),
        AddIV(seed=iv_seed),
        CBCEncrypt('aes', key),
    ])
    iv_rng = random.Random(iv_seed)
    for _ in range(5):
        message = random.randbytes(random.randint(10, 20))
        iv = iv_rng.randbytes(16)
        reference_cipher = AES.new(key, AES.MODE_CBC, iv)
        expected_out = pkcs7(message, AES.block_size)
        expected_out = reference_cipher.encrypt(expected_out)
        expected_out = iv + expected_out
        assert oracle(message) == expected_out
