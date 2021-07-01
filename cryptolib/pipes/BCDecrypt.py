from typing import Optional

from .Pipe import Pipe

from ..blockciphers import ECBMode, CBCMode
from ..utils.byteops import bytes_to_blocks


class BCDecrypt(Pipe):
    """A block cipher decryption pipeline component.

    Takes in a message of encrypted bytes and decrypts it using a specified block cipher mode, algorithm, key, and IV.

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
            The encryption key used to key the algorithm.
        iv
            The "Initialisation Vector" used to initialise the block cipher mode. Raises an exception if not provided unless the ECB mode is chosen, in which case one is not needed.

    Methods:
        __call__
            Decrypts the provided message.
        set_iv
            Sets the iv to the provided value.
    """

    def __init__(self,
                 mode: str,
                 algorithm: str,
                 key: bytes,
                 iv: Optional[bytes] = None):
        if mode.lower() == "ecb":
            if iv:
                raise ValueError("ECB mode takes no iv.")
            self.cipher = ECBMode(algorithm, key)
        else:
            if not iv:
                raise ValueError("iv is required for all modes besides ECB")
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
        cipher_blocks = self.cipher.decrypt(message_blocks)
        return b''.join(cipher_blocks)
