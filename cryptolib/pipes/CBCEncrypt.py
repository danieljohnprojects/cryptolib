import secrets
from typing import Optional

from ..blockciphers import engine_generators
from ..utils.byteops import block_xor, bytes_to_blocks

from .Pipe import Pipe


class CBCEncrypt(Pipe):
    def __init__(self,
                 algorithm: str,
                 key: Optional[bytes] = None):
        if not key:
            key = secrets.token_bytes(16)
        self._engine = engine_generators[algorithm.lower()](key)
        self.block_size = self._engine.block_size

    def __call__(self, message: bytes) -> bytes:
        message_blocks = bytes_to_blocks(message, self.block_size)
        cipher_blocks = [self.parent.iv]
        for block in message_blocks:
            cipher_in = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_in))
        return b''.join(cipher_blocks[1:])
