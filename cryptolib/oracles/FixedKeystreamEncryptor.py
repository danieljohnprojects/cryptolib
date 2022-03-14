from typing import Callable, Optional
from ..pipes import Pipe

from ..utils.byteops import block_xor

class FixedKeystreamEncyptor(Pipe):
    """
    Generates a fixed keystream and uses that to encrypt any message with length equal to the length of the keystream length.

    If a message is provided during initialisation it is encrypted with the keystream and made accesible via the get_encrypted_stream method. If no message is provided this method will return the raw keystream.

    Calling this oracle on a message will first check that the supplied message is the correct length, then xor it with the keystream.
    """
    def __init__(self,
                 keystream_generator: Callable,
                 message: Optional[bytes],
                 **kwargs):
        keystream = keystream_generator()
        if message is None:
            message = b'\x00'*len(keystream)

        kwargs['keystream'] = keystream
        kwargs['original_encrypted_stream'] = block_xor(keystream, message)

        super().__init__(**kwargs)

    def __call__(self, message: bytes) -> bytes:
        return block_xor(self.state['keystream'], message)

    def get_encrypted_stream(self):
        return self.state['original_encrypted_stream']
