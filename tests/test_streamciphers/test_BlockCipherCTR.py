import pytest
import random
from Crypto.Cipher import AES
from cryptolib.streamciphers.algorithms import BlockCipherCTR

def test_BlockCipherCTR():
    rng = random.Random(12345)

    cipher = BlockCipherCTR('aes', rng.randbytes(32), 1)
    cipher = BlockCipherCTR('aes', rng.randbytes(32), 15) 
    with pytest.raises(ValueError):
        cipher = BlockCipherCTR('aes', rng.randbytes(32), 0)
    with pytest.raises(ValueError):
        cipher = BlockCipherCTR('aes', rng.randbytes(32), 16)

    # Check nonce wrapping errors
    cipher = BlockCipherCTR('aes', rng.randbytes(32), 1)
    for _ in range(256):
        cipher.encrypt(b'a')
    with pytest.raises(RuntimeError):
        cipher.encrypt(b'a')

    # Check message length wrapping
    cipher = BlockCipherCTR('aes', rng.randbytes(32), 15)
    cipher.encrypt(b'a'*16*256) # Does not raise error
    with pytest.raises(ValueError):
        cipher.encrypt(b'a'*16*257)

    cipher.decrypt(b'n'*15 + b'a'*16*256)
    with pytest.raises(ValueError):
        cipher.decrypt(b'n'*15 + b'a'*16*257)

    # Check that encrypt and decrypt are inverses
    message = rng.randbytes(123)
    assert message == cipher.decrypt(cipher.encrypt(message))

    # Check against pycryptodome implementation
    nonce_size = 8
    key_lens = [16] * 10 + [24] * 10 + [32] * 10
    for key_len in key_lens:
        key = rng.randbytes(key_len)
        cipher = BlockCipherCTR('aes', key, nonce_size)
        message = rng.randbytes(rng.randint(10, 200))
        enc_message = cipher.encrypt(message)

        reference_cipher = AES.new(key, AES.MODE_CTR, nonce=enc_message[:nonce_size])
        expected_out = reference_cipher.encrypt(message)
        assert enc_message[nonce_size:] == expected_out
