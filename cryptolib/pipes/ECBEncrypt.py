import secrets
from typing import Optional

from .Pipe import Pipe

from ..blockciphers import engine_generators
from ..utils.byteops import bytes_to_blocks


class ECBEncrypt(Pipe):
    """
    A pipe that encrypts strings of bytes using the specified algorithm in ECB mode.

    Messages must be padded out to the correct length before being passed to the pipe.
    """

    def __init__(self,
                 algorithm: str,
                 key: Optional[bytes] = None,
                 **kwargs):

        engine_generating_function, key_size = engine_generators[algorithm.lower()]
        if not key:
            key = secrets.token_bytes(key_size)
        engine = engine_generating_function(key)
        kwargs['engine'] = engine
        kwargs['block_size'] = engine.block_size
        super().__init__(**kwargs)

    def __call__(self, message: bytes) -> bytes:

        message_blocks = bytes_to_blocks(message, self.state['block_size'])
        cipher_blocks = []
        for block in message_blocks:
            cipher_blocks.append(self.state['engine'].encrypt(block))
        return b''.join(cipher_blocks)
