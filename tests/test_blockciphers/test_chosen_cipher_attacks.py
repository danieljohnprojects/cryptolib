import pytest
import random

from Crypto.Cipher import AES

from cryptolib.blockciphers.attacks.chosen_cipher import decrypt_padding_oracle_cbc
from cryptolib.blockciphers.oracles import CBCoracle
from cryptolib.utils.padding import strip_pkcs7


def test_decrypt_padding_oracle_cbc():
    rng = random.Random(12345)
    plaintext = b'asdfjkl;qweruiopzxcvnm,.'

    enc, oracle = CBCoracle('aes', rng.randbytes(16))

    ciphertext = enc(plaintext)

    decrypted = strip_pkcs7(
        decrypt_padding_oracle_cbc(oracle, ciphertext, 16), 16)
    assert plaintext == decrypted

    ciphertext = b'a'*31
    with pytest.raises(ValueError):
        decrypt_padding_oracle_cbc(oracle, ciphertext, 16)
    ciphertext = b'a'*40
    with pytest.raises(ValueError):
        decrypt_padding_oracle_cbc(oracle, ciphertext, 16)
    ciphertext = b'a'*32
    with pytest.raises(RuntimeError):
        decrypt_padding_oracle_cbc(oracle, ciphertext, 16)
