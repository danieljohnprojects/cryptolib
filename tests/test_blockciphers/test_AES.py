import pytest
import random

from cryptolib.blockciphers.algorithms import AES

random.seed(1)

def test_init():
    # Assert that AES engine can only be initialised with a valid key
    for n in range(16):
        try:
            AES(random.randbytes(n))
        except ValueError:
            assert True
        else:
            assert False

def test_encrypt():
    # Assert that AES engine can only encrypt messages of the right length
    for n in [16,24,32]:
        engine = AES(random.randbytes(n))
        for _ in range(20):
            try:
                engine.encrypt(b'a' * random.randint(0,15))
            except ValueError:
                assert True
            else:
                assert False
            try:
                engine.encrypt(b'a' * random.randint(17,50))
            except ValueError:
                assert True
            else:
                assert False
    engine.encrypt(b'a' * 16)
    
def test_decrypt():
    # Assert that AES engine can only decrypt message of the correct length
    for n in [16,24,32]:
        engine = AES(random.randbytes(n))
        for _ in range(20):
            try:
                engine.decrypt(b'a' * random.randint(0,15))
            except ValueError:
                assert True
            else:
                assert False
            try:
                engine.decrypt(b'a' * random.randint(17,50))
            except ValueError:
                assert True
            else:
                assert False
    engine.decrypt(b'a' * 16)
