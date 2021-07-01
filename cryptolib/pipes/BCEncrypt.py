import secrets

from typing import Optional

from .Pipe import Pipe

from ..blockciphers import ECBMode, CBCMode
from ..utils.byteops import bytes_to_blocks


class BCEncrypt(Pipe):
    """A block cipher encryption pipeline component.

    Takes in a message of bytes and encrypts it using a specified block cipher mode, algorithm, key, and IV.

    Construction Arguments:
        mode 
            The block cipher mode to use. Must be one of:
            -ECB
            -CBC
            inputted as a string (case insensitive).
        algorithm  
            The algorithm of the underlying block cipher. Must be one of:
            -AES
            inputted as a string (case insensitive).
        key
            The encryption key used to key the algorithm. If not provided a random one is generated.
        iv
            The "Initialisation Vector" used to initialise the block cipher mode. If not provided a random one is generated except if the ECB mode is chosen, in which case one is not needed.

    Methods:
        __call__
            Encrypts the provided message.
        set_iv
            Sets the iv to the provided value.
    """

    def __init__(self,
                 mode: str,
                 algorithm: str,
                 key: Optional[bytes] = None,
                 iv: Optional[bytes] = None):
        # First initialise the encryption engine
        if not key:
            key = secrets.token_bytes(16)
        if mode.lower() == "ecb":
            if iv:
                raise ValueError("ECB mode takes no iv.")
            self.cipher = ECBMode(algorithm, key)
        else:
            if not iv:
                iv = secrets.token_bytes(16)
            if mode.lower() == "cbc":
                self.cipher = CBCMode(algorithm, key, iv)
            else:
                raise ValueError(f"{mode} is not a recognised mode.")

    def set_iv(self, iv: bytes):
        """Sets the iv of the underlying encryption engine to the provided value."""
        self.cipher.iv = iv

    def __call__(self, message: bytes) -> bytes:
        """Encrypts the message with the internal block cipher engine."""
        message_blocks = bytes_to_blocks(message, self.cipher.block_size)
        cipher_blocks = self.cipher.encrypt(message_blocks)
        return b''.join(cipher_blocks)
