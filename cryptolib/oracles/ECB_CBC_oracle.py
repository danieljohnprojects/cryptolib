import secrets

from ..blockciphers import CBCMode, ECBMode
from .BCOracle import BCOracle

class ECB_CBC_oracle(BCOracle):
    """
    Takes in a message of bytes, alters it and then encrypts with either ECB or CBC under a random key.
    """
    def __init__(self):
        self._cbc = lambda : CBCMode(
            'AES', 
            secrets.token_bytes(16), 
            IV=secrets.token_bytes(16), 
            padding='pkcs7')
        self._ecb = lambda : ECBMode(
            'AES', 
            secrets.token_bytes(16), 
            padding='pkcs7')
        # Need a way to test our predictions of the oracle.
        self._last_choice = None


    def divine(self, message: bytes) -> bytes:
        # Create a new cipher and discard it each call so that the key cannot be found
        cipher, self._last_choice = secrets.choice([(self._cbc(), 'CBC'), (self._ecb(), 'ECB')])
        prefix = secrets.token_bytes(secrets.choice(range(5, 11)))
        suffix = secrets.token_bytes(secrets.choice(range(5, 11)))
        return cipher.encrypt(prefix + message + suffix)
