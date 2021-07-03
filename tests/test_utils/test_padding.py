import pytest
from cryptolib.utils.padding import pkcs7, strip_pkcs7, is_valid_pkcs7

def test_is_valid_pkcs7():
    block_size = 16
    test_vectors = [
        (b'a', False),
        (b'\x10'*block_size, True),
        (b'\x20'*2*block_size, False), 
    ]
    test_vectors += [
        (b'\x00' * (block_size - n) + bytes([n])*n, True) 
        for n in range(1, block_size+1)
    ]
    for message, result in test_vectors:
        assert is_valid_pkcs7(message) == result

    try:
        is_valid_pkcs7(message, -1)
    except ValueError:
        assert True
    else:
        assert False

def test_pkcs7():
    block_size = 16
    test_vectors = [b'a'*n for n in range(32)]
    padded_vectors = [pkcs7(v, block_size) for v in test_vectors]
    for tv, pv in zip(test_vectors, padded_vectors):
        assert is_valid_pkcs7(pv)
        assert tv == strip_pkcs7(pv, block_size)
