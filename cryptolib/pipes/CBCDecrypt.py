from ..blockciphers import engine_generators
from ..oracles import Oracle
from ..utils.byteops import block_xor, bytes_to_blocks


class CBCDecrypt(Oracle):
    def __init__(self,
                 algorithm: str,
                 key: bytes):
        self._engine = engine_generators[algorithm.lower()](key)
        self.block_size = self._engine.block_size

    def __call__(self, message: bytes) -> bytes:
        message_blocks = bytes_to_blocks(message, self.block_size)
        plain_blocks = []
        prev_block = self.parent.iv
        for block in message_blocks:
            plain_block = block_xor(self._engine.decrypt(block), prev_block)
            plain_blocks.append(plain_block)
            prev_block = block

        return b''.join(plain_blocks)
