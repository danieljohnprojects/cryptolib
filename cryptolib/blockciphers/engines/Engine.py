from abc import ABC, abstractclassmethod


class Engine(ABC):
    """
    An object that encrypts/decrypts a block of bytes using a pre-initialised key.

    The actual algorithm used to perform encryptions and decryptions is left for concrete implementations of the class.

    The key is fixed when the object is created. To encrypt messages with a different key one would need a new AES engine.

    Methods:
    - encrypt: Takes in a block of plaintext bytes and encrypts it.
    - decrypt: Takes in a block of encrypted bytes and decrypts it.
    """

    block_size = None

    @abstractclassmethod
    def __init__(self, key: bytes):
        pass

    @abstractclassmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

    @abstractclassmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
