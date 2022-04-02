import pytest
import random

from Crypto.Cipher import AES

from cryptolib.blockciphers.chosen_cipher.attacks import decrypt_padding_oracle_cbc
from cryptolib.blockciphers.chosen_cipher.oracles import PaddingCBC, DecryptCBC, DecryptCBC_key_as_iv, DecryptCFB, DecryptECB, DecryptOFB
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC
from cryptolib.utils.padding import pkcs7, strip_pkcs7

def test_oracles():
    rng = random.Random(12345)
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        message = rng.randbytes(48)
        padded = pkcs7(message, 16)
        iv = rng.randbytes(16)

        enc_cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = enc_cipher.encrypt(padded)
        oracle = DecryptECB('aes', key)
        assert oracle(ciphertext) == message

        enc_cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = iv + enc_cipher.encrypt(padded)
        oracle = DecryptCBC('aes', key)
        assert oracle(ciphertext) == message

        enc_cipher = AES.new(key, AES.MODE_CBC, key[:16])
        ciphertext = enc_cipher.encrypt(padded)
        oracle = DecryptCBC_key_as_iv('aes', key)
        assert oracle(ciphertext) == message

        # enc_cipher = AES.new(key, AES.MODE_OFB, iv)
        # ciphertext = iv + enc_cipher.encrypt(padded)
        # oracle = DecryptOFB('aes', key)
        # assert oracle(ciphertext) == message

        enc_cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        ciphertext = iv + enc_cipher.encrypt(padded)
        oracle = DecryptCFB('aes', key)
        assert oracle(ciphertext) == message

def test_decrypt_padding_oracle_cbc():
    rng = random.Random(12345)
    plaintext = b'asdfjkl;qweruiopzxcvnm,.'
    key = rng.randbytes(16)
    ciphertext = EncryptCBC('aes', key)(plaintext)
    oracle = PaddingCBC('aes', key)
    del key
    decrypted = strip_pkcs7(decrypt_padding_oracle_cbc(oracle, ciphertext, 16), 16)
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
