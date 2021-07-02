from ..oracles import Oracle
from ..utils.padding import strip_pkcs7


class StripPKCS7(Oracle):
    """Pads a message to be a multiple of the block size."""

    def __init__(self, block_size: int = 16):
        self.block_size = block_size

    def __call__(self, message: bytes) -> bytes:
        return strip_pkcs7(message, self.block_size)
