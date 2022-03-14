from cryptolib.utils.byteops import block_xor
from .data import challenge25


def test_challenge25():
    ciphertext = challenge25.random_access_encryptor.get_encrypted_stream()
    keystream = challenge25.random_access_encryptor(b'\x00'*len(ciphertext))
    assert block_xor(ciphertext, keystream) == challenge25.plaintext


