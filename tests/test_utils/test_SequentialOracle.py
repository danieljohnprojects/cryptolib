import pytest
import random

from Crypto.Cipher import AES

from cryptolib.utils.SequentialOracle import SequentialOracle
from cryptolib.utils.padding import pkcs7


def test_SequentialOracle():
    rng = random.Random(12345)

    # Constant oracle
    oracle = SequentialOracle([
        lambda message: b''
    ])
    for _ in range(5):
        assert(oracle(rng.randbytes(rng.randint(10, 20))) == b'')

    # Identity oracle
    oracle = SequentialOracle([lambda message: message])
    for _ in range(5):
        message = rng.randbytes(10)
        assert oracle(message) == message

    # Prefix oracle
    prefix = rng.randbytes(6)
    oracle.prepend_pipe(
        lambda message: prefix + message
    )
    for _ in range(5):
        message = rng.randbytes(rng.randint(10, 20))
        assert(oracle(message) == prefix + message)

    # Prefix and suffix oracle
    suffix = rng.randbytes(rng.randint(10, 20))
    oracle.append_pipe(lambda message: message + suffix)
    for _ in range(5):
        message = rng.randbytes(rng.randint(10, 20))
        assert(oracle(message) == prefix + message + suffix)
