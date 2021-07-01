from ..blockciphers import engine_generators
from ..utils.byteops import bytes_to_blocks

from .Pipe import Pipe


class ECBDecrypt(Pipe):
    def __init__(self,
                 algorithm: str,
                 key: bytes):
        self._engine = engine_generators[algorithm.lower()](key)
        self.block_size = self._engine.block_size

    def __call__(self, message: bytes) -> bytes:
        message_blocks = bytes_to_blocks(message, self.block_size)
        plain_blocks = []
        for block in message_blocks:
            plain_block = self._engine.decrypt(block)
            plain_blocks.append(plain_block)

        return b''.join(plain_blocks)
