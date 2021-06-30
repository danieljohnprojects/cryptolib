import pytest
import random

from  Crypto.Cipher import AES
from cryptolib.oracles import Oracle
from cryptolib.pipes import BCEncryptPipe

random.seed(1)

def test_ECB_encryption():
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = random.randbytes(key_len)

        reference_cipher = AES.new(key, AES.MODE_ECB)

        pipe = BCEncryptPipe(
            'ecb', 
            'aes', 
            key=key
        )
        oracle = Oracle([pipe])

        message = random.randbytes(48)
        enc_message = oracle.divine(message)
        expected_out = reference_cipher.encrypt(message)
        assert enc_message==expected_out

def test_CBC_encryption():
    key_lens = [16, 24, 32]
    for key_len in key_lens:
        key = random.randbytes(key_len)
        pipe = BCEncryptPipe(
            'cbc', 
            'aes', 
            key=key
        )
        for _ in range(10):
            iv = random.randbytes(16)
            pipe.set_iv(iv)
            reference_cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            oracle = Oracle([pipe])

            message = random.randbytes(48)
            enc_message = oracle.divine(message)
            expected_out = reference_cipher.encrypt(message)
            assert enc_message==expected_out

