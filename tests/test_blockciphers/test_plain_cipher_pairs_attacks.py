from pydoc import plain
import pytest
import random

from cryptolib.blockciphers.plain_cipher_pairs.attacks import exhaust_key, splice_ECB_ciphertext
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

def test_splice_ECB_ciphertext():
    rng = random.Random(12345)
    key = rng.randbytes(16)
    enc = EncryptECB('aes', key)
    p1 = b'Please send: $15 to Alice.'
    p2 = b'Please send: $0.05 to Bob.'
    c1 = enc(p1)
    c2 = enc(p2)
    p3, c3 = splice_ECB_ciphertext( ((p1, c1), (p2, c2)), 16 )
    assert enc(p3) == c3