import pytest
import random

from Crypto.Cipher import AES

from cryptolib.blockciphers.attacks.chosen_cipher import decrypt_padding_oracle_cbc
from cryptolib.blockciphers.chosen_cipher.oracles import PaddingCBC, DecryptCBC, DecryptCBC_key_as_iv, DecryptCFB, DecryptECB, DecryptOFB
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC
from cryptolib.utils.padding import pkcs7, strip_pkcs7


def test_decrypt_padding_oracle_cbc():
    rng = random.Random(12345)
    plaintext = b'asdfjkl;qweruiopzxcvnm,.'
    key = rng.randbytes(16)
    ciphertext = EncryptCBC('aes', key)(plaintext)
    oracle = PaddingCBC('aes', key)
    del key
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
