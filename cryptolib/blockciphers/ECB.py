from typing import Sequence
from .Mode import Mode


class ECBMode(Mode):
    """A block cipher in ECB mode.

    ECB mode encrypts and decrypts each block separately without the use of an IV or nonce.

    Note that ECB mode is not secure for messages longer than a single block. Repeated blocks of plaintext will encrypt to the same blocks of ciphertext.
    """

    def __init__(self,
                 algorithm: str,
                 key: bytes):
        super().__init__(algorithm, key)

    def encrypt(self,
                message_blocks: Sequence[bytes]
                ) -> Sequence[bytes]:
        cipher_blocks = []
        for block in message_blocks:
            cipher_blocks.append(self._engine.encrypt(block))
        return cipher_blocks

    def decrypt(self,
                cipher_blocks: Sequence[bytes]
                ) -> Sequence[bytes]:
        plain_blocks = []
        for block in cipher_blocks:
            plain_blocks.append(self._engine.decrypt(block))
        return plain_blocks
