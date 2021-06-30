from cryptolib.utils.byteops import bytes_to_blocks
from cryptolib.utils.padding import Padder
import secrets

# from ..blockciphers import CBCMode, ECBMode
from .Oracle import Oracle

from ..pipes import BCEncryptPipe, PadPKCS7Pipe

class ECB_CBC_oracle(Oracle):
    """
    Takes in a message of bytes, alters it and then encrypts with either ECB or CBC under a random key.
    """
    def __init__(self):
        self.pipeline = [
            self.add_prefix,
            self.add_suffix,
            PadPKCS7Pipe(),
            self.choose_engine_and_encrypt
        ]

        self._cbc = lambda : BCEncryptPipe(
            'cbc',
            'AES', 
            secrets.token_bytes(16), 
            iv=secrets.token_bytes(16), 
            )
        self._ecb = lambda : BCEncryptPipe(
            'ecb',
            'AES', 
            secrets.token_bytes(16), 
            )
        # Need a way to test our predictions of the oracle.
        self._last_choice = None

    @staticmethod
    def add_prefix(message: bytes) -> bytes:
        prefix = secrets.token_bytes(secrets.choice(range(5, 11)))
        return prefix + message

    @staticmethod
    def add_suffix(message: bytes) -> bytes:
        suffix = secrets.token_bytes(secrets.choice(range(5, 11)))
        return message + suffix

    def choose_engine_and_encrypt(self, message: bytes) -> bytes:
        cipher, self._last_choice = secrets.choice([(self._cbc(), 'CBC'), (self._ecb(), 'ECB')])
        return cipher(message)
