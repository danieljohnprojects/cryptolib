from ctypes import *
from ...utils.files import build_filename

libpath = build_filename('build/SHA/libSHA1.so')
SHA1libC = CDLL(libpath)
init_buffer = bytes.fromhex('67452301efcdab8998badcfe10325476c3d2e1f0')


def sha1digest(message: bytes) -> bytes:
    """
    Compute the SHA1 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 20-byte SHA1 hash.
    """
    digest_buffer = create_string_buffer(init_buffer, len(init_buffer))
    SHA1libC.sha1digest(message, len(message), 0, digest_buffer)
    return digest_buffer.raw

def sha1extend(prev_hash: bytes, prev_len: int, message: bytes) -> bytes:
    """
    Extend the given SHA1 hash to a hash of the original message plus padding concatenated with a new message.

    Args:
        prev_hash: The SHA1 hash of a message. Nothing about the original message itself need be known except for its length.
        prev_len: The length of the original message.
        message: The message to append to the original message (plus padding).
    Returns:
        The hash of the original message plus padding with the new message appended.
    Raises:
        ValueError: If prev_hash has the incorrect length.
    """
    if len(prev_hash) != len(init_buffer):
        raise ValueError(f"Previous hash must have length {len(init_buffer)}. Got {len(prev_hash)}.")
    digest_buffer = create_string_buffer(prev_hash, len(prev_hash))
    SHA1libC.sha1digest(message, len(message), prev_len, digest_buffer)
    return digest_buffer.raw
