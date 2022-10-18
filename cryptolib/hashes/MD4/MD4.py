from ctypes import *
from ...utils.files import build_filename

libpath = build_filename('build/lib/MDHashes/libMD4.so')
MD4libC = CDLL(libpath)
init_buffer = bytes.fromhex("0123456789abcdeffedcba9876543210")


def md4digest(message: bytes) -> bytes:
    """
    Compute the MD4 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 16-byte MD4 hash.
    Raises:
        TypeError: If message is not a byte-like object.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be a byte-like object. Got {type(message)}.")
    digest_buffer = create_string_buffer(init_buffer, len(init_buffer))
    MD4libC.md4digest(message, len(message), 0, digest_buffer)
    return digest_buffer.raw

def md4extend(prev_hash: bytes, prev_len: int, message: bytes) -> bytes:
    """
    Extend the given MD4 hash to a hash of the original message plus padding concatenated with a new message.

    Args:
        prev_hash: The MD4 hash of a message. Nothing about the original message itself need be known except for its length.
        prev_len: The length of the original message.
        message: The message to append to the original message (plus padding).
    Returns:
        The hash of the original message plus padding with the new message appended.
    Raises:
        ValueError: If prev_hash has the incorrect length.
        TypeError: If message is not a byte-like object.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be a byte-like object. Got {type(message)}.")
    if len(prev_hash) != len(init_buffer):
        raise ValueError(f"Previous hash must have length {len(init_buffer)}. Got {len(prev_hash)}.")
    digest_buffer = create_string_buffer(prev_hash, len(prev_hash))
    MD4libC.md4digest(message, len(message), prev_len, digest_buffer)
    return digest_buffer.raw

def md4extend_message(prefix_len: int, message: bytes, suffix: bytes) -> bytes:
    """
    Construct a length extended message that could for example pass a prefix MAC verification check.
    
    Args:
        prefix_len: The length of the unknown prefix that is added by a prefix MAC signing oracle.
        message: The message corresponding to the original MAC.
        suffix: A suffix to add on to the extended message.
    Returns:
        A message that should pass a prefix MAC verification oracle (the corresponding MAC can be calculated with the md4extend function). 
    """
    original_message_len = prefix_len + len(message)
    pad_len = (56 - original_message_len) % 64
    padding = b'\x80' + b'\x00' * (pad_len-1)
    length_block = (8*original_message_len).to_bytes(8, 'little') # length in *bits*
    return message + padding + length_block + suffix