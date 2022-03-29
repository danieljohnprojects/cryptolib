from ctypes import *
from .BCEngine import BCEngine
from ...utils.files import build_filename

class AES(BCEngine):
    """
    An object that encrypts/decrypts a block of bytes using AES.

    The key is fixed when the object is created. To encrypt messages with a different key one would need a new AES engine.

    Methods:
    - encrypt: Takes in a block of plaintext bytes and encrypts it.
    - decrypt: Takes in a block of encrypted bytes and decrypts it.
    """

    block_size = 16
    libpath128 = build_filename('build/AES/libaes128.so')
    libpath192 = build_filename('build/AES/libaes192.so')
    libpath256 = build_filename('build/AES/libaes256.so')
    AES128libC = CDLL(libpath128)
    AES192libC = CDLL(libpath192)
    AES256libC = CDLL(libpath256)

    def __init__(self, key: bytes):
        # Key can be either 128, 192, or 256 bits long.
        if len(key) == 16:
            key_schedule_len = 16 * 11  # 10 rounds plus initial key of 16 bytes
            self._libC = self.AES128libC
        elif len(key) == 24:
            key_schedule_len = 16 * 13  # 12 rounds plus initial key of 16 bytes
            self._libC = self.AES192libC
        elif len(key) == 32:
            key_schedule_len = 16 * 15  # 14 rounds plus initial key of 16 bytes
            self._libC = self.AES256libC
        else:
            raise ValueError(
                f"Key must be 16, 24, or 32 bytes long, got {len(key)}.")

        # Load library functions
        # Initialise the key schedule
        self._key_schedule = create_string_buffer(key_schedule_len)
        self._libC.initialise_key(key, self._key_schedule)

    def encrypt(self, message: bytes) -> bytes:
        if (len(message) != self.block_size):
            raise ValueError(
                f"Message length must be {self.block_size} bytes. Got {len(message)}.")

        ciphertext = create_string_buffer(self.block_size)
        self._libC.encrypt(self._key_schedule, message, ciphertext)
        return ciphertext.raw

    def decrypt(self, ciphertext: bytes) -> bytes:
        if (len(ciphertext) != self.block_size):
            raise ValueError(
                f"Ciphertext length must be f{self.block_size} bytes. Got {len(ciphertext)}.")

        plain = create_string_buffer(self.block_size)
        self._libC.decrypt(self._key_schedule, ciphertext, plain)
        return plain.raw
