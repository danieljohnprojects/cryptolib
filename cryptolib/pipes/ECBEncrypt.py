import secrets
from typing import Optional

from ..blockciphers import engine_generators
from ..oracles import Oracle
from ..utils.byteops import bytes_to_blocks


class ECBEncrypt(Oracle):
    def __init__(self,
                 algorithm: str,
                 key: Optional[bytes] = None,
                 **kwargs):
        if not key:
            key = secrets.token_bytes(16)
        engine = engine_generators[algorithm.lower()](key)
        kwargs['engine'] = engine
        kwargs['block_size'] = engine.block_size
        super().__init__(**kwargs)

    def __call__(self, message: bytes) -> bytes:
        message_blocks = bytes_to_blocks(message, self.state['block_size'])
        cipher_blocks = []
        for block in message_blocks:
            cipher_blocks.append(self.state['engine'].encrypt(block))
        return b''.join(cipher_blocks)
