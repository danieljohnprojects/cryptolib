import pytest
import random

from cryptolib.blockciphers.ciphertext_only.attacks import get_max_block_size, evidence_of_ECB
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC, EncryptECB

def test_get_max_block_size():
    ciphertexts = [
        b'aaa',
        b'aaaaaa'
    ]
    assert get_max_block_size(ciphertexts) == 3
    ciphertexts = [
        b'a'*32,
        b'a'*48
    ]
    assert get_max_block_size(ciphertexts) == 16

def test_evidence_of_ECB():
    rng = random.Random(12345)
    plaintext = b'a'*48
    key = rng.randbytes(16)

    ecb_enc = EncryptECB('aes', key)
    cbc_enc = EncryptCBC('aes', key)
    ciphertext_ecb = ecb_enc(plaintext)
    ciphertext_cbc = cbc_enc(plaintext)

    assert evidence_of_ECB(ciphertext_ecb)
    assert not evidence_of_ECB(ciphertext_cbc)

    plaintexts = [b'a'*16 + b'b'*16, b'b'*16 + b'a'*16]

    ciphertexts_ecb = [ecb_enc(p) for p in plaintexts]
    ciphertexts_cbc = [cbc_enc(p) for p in plaintexts]

    assert evidence_of_ECB(ciphertexts_ecb)
    assert not evidence_of_ECB(ciphertexts_cbc)
