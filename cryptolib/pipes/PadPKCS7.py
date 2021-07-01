from .Pipe import Pipe

from ..utils.padding import pkcs7


class PadPKCS7(Pipe):
    """Pads a message to be a multiple of the block size."""

    def __init__(self, block_size: int = 16):
        self.block_size = block_size

    def __call__(self, message: bytes) -> bytes:
        return pkcs7(message, self.block_size)
