import os
from ctypes import *
from .Engine import Engine


class AES(Engine):
    """
    An object that encrypts/decrypts a block of bytes using AES.

    The key is fixed when the object is created. To encrypt messages with a different key one would need a new AES engine.

    Methods:
    - encrypt: Takes in a block of plaintext bytes and encrypts it.
    - decrypt: Takes in a block of encrypted bytes and decrypts it.
    """

    # Path to C library containing encrypt, decrypt and key initialisation
    # functions.
    _path_to_AES_libs = '/home/daniel/projects/cryptolib/build/lib/AES'
    block_size = 16

    def __init__(self, key: bytes):
        # Key can be either 128, 192, or 256 bits long.
        if len(key) == 16:
            libpath = os.path.join(self._path_to_AES_libs, "libaes128.so")
            key_schedule_len = 16 * 11  # 10 rounds plus initial key of 16 bytes
        elif len(key) == 24:
            libpath = os.path.join(self._path_to_AES_libs, "libaes192.so")
            key_schedule_len = 16 * 13  # 12 rounds plus initial key of 16 bytes
        elif len(key) == 32:
            libpath = os.path.join(self._path_to_AES_libs, "libaes256.so")
            key_schedule_len = 16 * 15  # 14 rounds plus initial key of 16 bytes
        else:
            raise ValueError(
                f"Key must be 16, 24, or 32 bytes long, got {len(key)}.")

        # Load library functions
        self._AESlibC = CDLL(libpath)
        # Initialise the key schedule
        self._key_schedule = create_string_buffer(key_schedule_len)
        self._AESlibC.initialise_key(key, self._key_schedule)

    def encrypt(self, message: bytes) -> bytes:
        if (len(message) != self.block_size):
            raise ValueError(
                f"Message length must be f{self.block_size} bytes. Got {len(message)}.")

        ciphertext = create_string_buffer(self.block_size)
        self._AESlibC.encrypt(self._key_schedule, message, ciphertext)
        return ciphertext.raw

    def decrypt(self, ciphertext: bytes) -> bytes:
        if (len(ciphertext) != self.block_size):
            raise ValueError(
                f"Ciphertext length must be f{self.block_size} bytes. Got {len(ciphertext)}.")

        plain = create_string_buffer(self.block_size)
        self._AESlibC.decrypt(self._key_schedule, ciphertext, plain)
        return plain.raw
