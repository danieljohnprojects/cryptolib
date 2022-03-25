"""
A collection of oracles that can be attacked with chosen ciphertext attacks.
"""

from ..algorithms import engine_generators
from ..chosen_plain.oracles import EncryptOFB
from ...utils.byteops import block_xor, bytes_to_blocks
from ...utils.padding import strip_pkcs7


class DecryptECB:
    """
    An oracle that decrypts the supplied string of bytes using the specified algorithm and key in ECB mode.
    """

    def __init__(self,
                 algorithm: str,
                 key: bytes):

        engine_generating_function, _ = engine_generators[algorithm.lower()]
        self._engine = engine_generating_function(key)
        self._block_size = self._engine.block_size

    def __call__(self, ciphertext: bytes) -> bytes:
        cipher_blocks = bytes_to_blocks(ciphertext, self._block_size)
        message_blocks = [self._engine.decrypt(block) for block in cipher_blocks]

        message = b''.join(message_blocks)
        return strip_pkcs7(message, self._block_size)


class DecryptCBC(DecryptECB):
    """
    An oracle that decrypts the supplied string of bytes using the specified algorithm, and key in CBC mode. The first block of ciphertext is assumed to be the IV.
    """
    def __call__(self, ciphertext: bytes) -> bytes:
        cipher_blocks = bytes_to_blocks(ciphertext, self._block_size)
        cipher_output = [self._engine.decrypt(block) for block in cipher_blocks[1:]]
        plain_blocks = [block_xor(cblock, outblock) for cblock, outblock in zip(cipher_blocks[:-1], cipher_output)]
        message = b''.join(plain_blocks)
        return strip_pkcs7(message, self._block_size)


class DecryptCFB(DecryptECB):
    """
    An oracle that decrypts the supplied string of bytes using the specified algorithm, and key in CFB mode. The first block of ciphertext is assumed to be the IV.
    """
    def __call__(self, ciphertext: bytes) -> bytes:
        cipher_blocks = bytes_to_blocks(ciphertext, self._block_size)
        cipher_output = [self._engine.encrypt(block) for block in cipher_blocks[:-1]]
        plain_blocks = [block_xor(cblock, outblock) for cblock, outblock in zip(cipher_blocks[1:], cipher_output)]
        message = b''.join(plain_blocks)
        return strip_pkcs7(message, self._block_size)


class DecryptOFB(EncryptOFB):
    """
    An oracle that decrypts the supplied string of bytes using the specified algorithm, and key in OFB mode. The first block of ciphertext is assumed to be the IV.

    Note that in OFB there is no difference between encryption and decryption
    """
    pass
