from ctypes import *
from ...utils.files import build_filename

libpath = build_filename('build/lib/SHA/libSHA1.so')
SHA1libC = CDLL(libpath)

block_t = c_uint32 * 5
def init_buffer_from_bytes(b: bytes): 
    return block_t(
        int.from_bytes(b[  : 4], 'big', signed=False),
        int.from_bytes(b[ 4: 8], 'big', signed=False),
        int.from_bytes(b[ 8:12], 'big', signed=False),
        int.from_bytes(b[12:16], 'big', signed=False),
        int.from_bytes(b[16:  ], 'big', signed=False)
    )

def sha1extend(prev_hash: bytes, prev_len: int, message: bytes) -> bytes:
    """
    Extend the given SHA1 hash to a hash of the original message plus padding concatenated with a new message.

    Args:
        prev_hash: The SHA1 hash of a message. Nothing about the original message itself need be known except for its length.
        prev_len: The length of the original message (in bytes).
        message: The message to append to the original message (plus padding).
    Returns:
        The hash of the original message plus padding with the new message appended.
    Raises:
        ValueError: If prev_hash has the incorrect length.
        TypeError: If message is not a byte-like object.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be a byte-like object. Got {type(message)}.")
    if len(prev_hash) != 20:
        raise ValueError(f"Previous hash must have length {len(init_buffer)}. Got {len(prev_hash)}.")    
    digest_buffer = init_buffer_from_bytes(prev_hash)
    SHA1libC.sha1digest(message, len(message), prev_len, digest_buffer)
    digest = b''.join([i.to_bytes(4, 'big') for i in digest_buffer])
    return digest

def sha1digest(message: bytes) -> bytes:
    """
    Compute the SHA1 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 20-byte SHA1 hash.
    Raises:
        TypeError: If message is not a byte-like object.
    """
    return sha1extend(
        bytes.fromhex('67452301efcdab8998badcfe10325476c3d2e1f0'), 
        0, 
        message
    )

def sha1extend_message(prefix_len: int, message: bytes, suffix: bytes) -> bytes:
    """
    Construct a length extended message that could for example pass a prefix MAC verification check.
    
    Args:
        prefix_len: The length of the unknown prefix that is added by a prefix MAC signing oracle.
        message: The message corresponding to the original MAC.
        suffix: A suffix to add on to the extended message.
    Returns:
        A message that should pass a prefix MAC verification oracle (the corresponding MAC can be calculated with the sha1extend function). 
    """
    original_message_len = prefix_len + len(message)
    pad_len = (56 - original_message_len) % 64
    padding = b'\x80' + b'\x00' * (pad_len-1)
    length_block = (8*original_message_len).to_bytes(8, 'big') # length in *bits*
    return message + padding + length_block + suffix