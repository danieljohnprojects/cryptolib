from pydoc import plain
import pytest
import random

from cryptolib.blockciphers.plain_cipher_pairs.attacks import exhaust_key
from cryptolib.blockciphers.chosen_plain.oracles import EncryptECB

def test_exhaust_key():
    rng = random.Random(12345)
    key = rng.randbytes(2) # 16 bits
    key = b'\x00' * 14 + key
    plaintext = b'a'*16
    enc = EncryptECB('aes', key)
    ciphertext = enc(plaintext)

    assert key == exhaust_key(
        plaintext, 
        ciphertext, 
        lambda key: EncryptECB('aes', key), 
        16, 
        16)

    key = b'\xf0' + b'\x00'*15
    enc = EncryptECB('aes', key)
    ciphertext = enc(plaintext)
    with pytest.raises(RuntimeError):
        exhaust_key(plaintext, ciphertext, lambda key: EncryptECB('aes', key), 16, 16)
