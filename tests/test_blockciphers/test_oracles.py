import pytest
import random

from Crypto.Cipher import AES

from cryptolib.blockciphers.oracles import ECBoracle, CBCoracle, CBCoracle_KeyAsIV
from cryptolib.utils.padding import pkcs7


def test_ECBoracle():
    rng = random.Random(12345)
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        message = rng.randbytes(48)
        padded = pkcs7(message, 16)

        reference_cipher = AES.new(key, AES.MODE_ECB)
        test_enc, test_dec = ECBoracle('aes', key)
        ciphertext = reference_cipher.encrypt(padded)
        assert test_enc(message) == ciphertext
        assert test_dec(ciphertext) == message


def test_CBCoracle():
    rng = random.Random(12345)
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        message = rng.randbytes(48)
        padded = pkcs7(message, 16)

        test_enc, test_dec = CBCoracle('aes', key)
        ciphertext = test_enc(message)
        iv = ciphertext[:16]
        reference_cipher = AES.new(key, AES.MODE_CBC, iv)
        assert reference_cipher.encrypt(padded) == ciphertext[16:]
        assert test_dec(ciphertext) == message


def test_CBCoracle_KeyAsIV():
    rng = random.Random(12345)
    key_lens = [16] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        message = rng.randbytes(48)
        padded = pkcs7(message, 16)

        test_enc, test_dec = CBCoracle_KeyAsIV(key)
        ciphertext = test_enc(message)
        reference_cipher = AES.new(key, AES.MODE_CBC, key)
        assert reference_cipher.encrypt(padded) == ciphertext
        assert test_dec(ciphertext) == message
