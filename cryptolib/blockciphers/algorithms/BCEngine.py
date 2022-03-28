from abc import ABC, abstractmethod
class BCEngine(ABC):
    """
    An object that encrypts/decrypts a block of bytes using a pre-initialised key.

    The actual algorithm used to perform encryptions and decryptions is left for concrete implementations of the class.

    The key is fixed when the object is created. To encrypt messages with a different key one would need a new engine.

    Methods:
    - encrypt: Takes in a block of plaintext bytes and encrypts it.
    - decrypt: Takes in a block of encrypted bytes and decrypts it.
    """

    block_size = None

    @abstractmethod
    def __init__(self, key: bytes):
        pass

    @abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
