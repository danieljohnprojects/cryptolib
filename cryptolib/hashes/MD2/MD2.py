from ctypes import *
from ...utils.files import build_filename

libpath = build_filename('build/lib/MDHashes/libMD2.so')
MD2libC = CDLL(libpath)
init_buffer = bytes(16)


def md2digest(message: bytes) -> bytes:
    """
    Compute the MD2 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 16-byte MD2 hash.
    """
    digest_buffer = create_string_buffer(init_buffer, len(init_buffer))
    MD2libC.md2digest(message, len(message), digest_buffer)
    return digest_buffer.raw