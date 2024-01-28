import pytest
import random

from Crypto.PublicKey import RSA

from cryptolib.maths.primes import miller_rabin_test
from cryptolib.publickey.RSA import TextbookRSAOracle, TextbookRSAEncrypt, RSAPublicKey, RSADecryptor


def test_TextbookRSA():
    rng = random.Random(12345)
    modulus_bits = 1024
    message = rng.randbytes(modulus_bits//8 - 1)
    message_int = int.from_bytes(message, "big")

    ref_keys = RSA.generate(modulus_bits, rng.randbytes, e=3)
    ref_pk = ref_keys.publickey()
    ref_cipher_int = ref_pk._encrypt(message_int)
    ref_cipher_bytes = ref_cipher_int.to_bytes(modulus_bits // 8)

    pk = RSAPublicKey(ref_pk.n, ref_pk.e)
    ciphertext = TextbookRSAEncrypt(pk, message)

    assert ciphertext == ref_cipher_bytes
