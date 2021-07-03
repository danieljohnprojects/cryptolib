from .Pipe import Pipe

from ..blockciphers import engine_generators
from ..utils.byteops import bytes_to_blocks


class ECBDecrypt(Pipe):
    def __init__(self,
                 algorithm: str,
                 key: bytes,
                 **kwargs):
        engine = engine_generators[algorithm.lower()](key)
        kwargs['engine'] = engine
        kwargs['block_size'] = engine.block_size
        super().__init__(**kwargs)

    def __call__(self, message: bytes) -> bytes:
        message_blocks = bytes_to_blocks(message, self.state['block_size'])
        plain_blocks = []
        for block in message_blocks:
            plain_block = self.state['engine'].decrypt(block)
            plain_blocks.append(plain_block)

        return b''.join(plain_blocks)
