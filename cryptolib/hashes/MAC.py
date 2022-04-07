from typing import Callable
from ..utils.byteops import cyclical_xor

class prependMAC:
    """
    Generates a Message Authentication Code (MAC) by prepending a secret key to a message and then hashing. 
    """
    def __init__(self, hash_fn: Callable, key: bytes):
        """
        Instantiates a MAC object with the given key.

        Args:
            hash_fn - The underlying hash function used to compute a MAC. It is expected that this function takes in an arbitrary string of bytes and outputs a fixed-length digest.
            key - The authentication key.
        """
        self.hash = hash_fn
        self.key = key
    
    def __call__(self, message: bytes) -> bytes:
        """
        Computes the MAC of the given message.

        Internally computes H(key || message) where H is the hash function provided at instantiation.

        Args:
            message - An arbitrary length string of bytes.
        Returns:
            The MAC of the message.
        """
        return self.hash(self.key + message)

class HMAC(prependMAC):
    """
    Generates a Hash-based MAC (HMAC).
    """
    def __init__(self, hash_fn: Callable, key: bytes):
        blocksize = len(hash_fn(b''))
        key = key[:blocksize] + bytes(max(0, blocksize - len(key)))
        self._k1 = cyclical_xor(b'\x36', key)
        self._k2 = cyclical_xor(b'\x5c', key)
        self.hash = hash_fn

    def __call__(self, message: bytes) -> bytes:
        """
        Computes the HMAC of the given message.

        Internally computes H(k1 || H(k2 || message)).

        Args:
            message - An arbitrary length string of bytes.
        Returns:
            The HMAC of the message.
        """
        return self.hash(self._k1 + self.hash(self._k2 + message))