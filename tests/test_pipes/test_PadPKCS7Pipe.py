import pytest

from cryptolib.oracles import Oracle
from cryptolib.pipes import PadPKCS7Pipe

def test_pkcs7():
    oracle = Oracle([PadPKCS7Pipe()])
    test_vectors = [
        b'0',
        b'01',
        b'012',
        b'0123456789abcdef',
    ]
    expected_out = [
        b'0' + b'\x0f'*15,
        b'01' + b'\x0e'*14,
        b'012' + b'\x0d'*13,
        b'0123456789abcdef' + b'\x10'*16,
    ]
    for test_in, test_out in zip(test_vectors, expected_out):
        assert oracle.divine(test_in) == test_out