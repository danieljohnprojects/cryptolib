from cryptolib.utils.byteops import bytes_to_blocks
from cryptolib.utils.padding import Padder
import secrets

from ..blockciphers import CBCMode, ECBMode
from .Oracle import Oracle

class ECB_CBC_oracle(Oracle):
    """
    Takes in a message of bytes, alters it and then encrypts with either ECB or CBC under a random key.
    """
    def __init__(self):
        self._cbc = lambda : CBCMode(
            'AES', 
            secrets.token_bytes(16), 
            IV=secrets.token_bytes(16), 
            )
        self._ecb = lambda : ECBMode(
            'AES', 
            secrets.token_bytes(16), 
            )
        # Need a way to test our predictions of the oracle.
        self._last_choice = None
        self.padder = Padder('pkcs7', 16)


    def divine(self, message: bytes) -> bytes:
        # Create a new cipher and discard it each call so that the key cannot be found
        cipher, self._last_choice = secrets.choice([(self._cbc(), 'CBC'), (self._ecb(), 'ECB')])
        prefix = secrets.token_bytes(secrets.choice(range(5, 11)))
        suffix = secrets.token_bytes(secrets.choice(range(5, 11)))
        plain_blocks = bytes_to_blocks(prefix + message + suffix, cipher.block_size)
        cipher_blocks = cipher.encrypt(plain_blocks)
        ciphertext = b''.join(cipher_blocks)
        return ciphertext
