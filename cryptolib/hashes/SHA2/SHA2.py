from ctypes import *
from ..SHA1 import sha1extend_message
from ...utils.files import build_filename

libpath = build_filename('build/lib/SHA/libSHA256.so')
SHA256libC = CDLL(libpath)

block_t = c_uint32 * 8

def init_buffer_from_bytes(b: bytes):
    return block_t(
        int.from_bytes(b[  : 4], 'big', signed=False),
        int.from_bytes(b[ 4: 8], 'big', signed=False),
        int.from_bytes(b[ 8:12], 'big', signed=False),
        int.from_bytes(b[12:16], 'big', signed=False),
        int.from_bytes(b[16:20], 'big', signed=False),
        int.from_bytes(b[20:24], 'big', signed=False),
        int.from_bytes(b[24:28], 'big', signed=False),
        int.from_bytes(b[28:  ], 'big', signed=False),
    )

def sha256extend(prev_hash: bytes, prev_len: int, message: bytes) -> bytes:
    """
    Extend the given SHA256 hash to a hash of the original message plus padding concatenated with a new message.

    Args:
        prev_hash: The SHA256 hash of a message. Nothing about the original message itself need be known except for its length.
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
    if len(prev_hash) != 32:
        raise ValueError(f"Previous hash must have length {len(init_buffer)}. Got {len(prev_hash)}.")    
    digest_buffer = init_buffer_from_bytes(prev_hash)
    SHA256libC.sha256digest(message, len(message), prev_len, digest_buffer)
    digest = b''.join([i.to_bytes(4, 'big') for i in digest_buffer])
    return digest

def sha256digest(message: bytes) -> bytes:
    """
    Compute the SHA256 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 32-byte SHA256 hash.
    Raises:
        TypeError: If message is not a byte-like object.
    """
    return sha256extend(bytes.fromhex('6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'), 0, message)

def sha224digest(message: bytes) -> bytes:
    """
    Compute the SHA224 hash of the given message.

    Args:
        message: A string of bytes for which we will compute the hash.
    Returns:
        The 28-byte SHA224 hash.
    Raises:
        TypeError: If message is not a byte-like object.
    """
    return sha256extend(bytes.fromhex('c1059ed8367cd5073070dd17f70e5939ffc00b316858151164f98fa7befa4fa4'), 0, message)[:-4]

def sha256extend_message(prefix_len: int, message: bytes, suffix: bytes) -> bytes:
    """
    Construct a length extended message that could for example pass a prefix MAC verification check.
    
    Args:
        prefix_len: The length of the unknown prefix that is added by a prefix MAC signing oracle.
        message: The message corresponding to the original MAC.
        suffix: A suffix to add on to the extended message.
    Returns:
        A message that should pass a prefix MAC verification oracle (the corresponding MAC can be calculated with the sha256extend function). 
    """
    return sha1extend_message(prefix_len, message, suffix)