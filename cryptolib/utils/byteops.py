"""
Operations on byte objects.
"""


def block_xor(b1: bytes, b2: bytes) -> bytes:
    """
    Xors two byte objects of the same length together.
    """
    if len(b1) != len(b2):
        raise ValueError("Blocks must be of the same length.")
    return bytes([x ^ y for x, y in zip(b1, b2)])


def bytes_to_blocks(message: bytes, block_size: int) -> list[bytes]:
    """
    Chops up a message into blocks of length block_size.

    If the message is not a multiple of block_size the last block will have length less than block_size.
    """
    if block_size < 2:
        raise ValueError(f"block_size must be greater than 1. Got {block_size}.")
    if not message:
        return []
    blocks = [message[:block_size]]
    i = block_size
    while len(blocks[-1]) == block_size:
        block = message[i:i + block_size]
        if block:
            blocks.append(message[i: i+block_size])
            i += block_size
        else:
            break
    return blocks


def cyclical_xor(key: bytes, message: bytes) -> bytes:
    """
    Xors the key over the message cyclically.

    For example the given the key 0xabcd and the message 0x0123456789 the function computes the xor of 
        0x0123456789
      ^ 0xabcdabcdab
      --------------
        0xaaeeeeaa22

    Length of the output is equal to the length of the message.
    """
    q = len(message) // len(key)
    r = len(message) % len(key)
    long_key = key * q + key[:r]
    return block_xor(long_key, message)


def hamming_distance(m1: bytes, m2: bytes) -> int:
    """
    Determines the hamming distance between two messages of bytes.

    m1 and m2 should be the same length.

    Example:
    >>> m1 = bytes(b'this is a test')
    >>> m2 = bytes(b'wokka wokka!!!')
    >>> hamming_distance(m1, m2)
    37
    """
    if len(m1) != len(m2):
        raise ValueError("Messages must be the same length.")
    bits_different = cyclical_xor(m1, m2)
    return bin(int.from_bytes(bits_different, 'big')).count('1')


def transpose(messages: list[bytes]) -> list[bytes]:
    """
    Transposes a list of messages of the same length.
    
    For example the list [b'012', b'345'] would produce [b'03', b'14', b'25'].
    """
    assert all([len(message) == len(messages[0]) for message in messages])
    return [bytes([message[i] for message in messages]) for i in range(len(messages[0]))]


def reconstruct_from_str(s: str) -> bytes:
    """
    Reconstructs a bytes object that has been converted to a string. This sometimes happens in error messages and it's super annoying to get it back to the original bytes.

    For example an error might return the f-string
    f"Message {message} contains non-ascii characters!"
    Python puts in a bunch of \\s to print the message. This function removes all the extra formatting and returns the original bytes of the message variable.
    """
    s = s[2:-1] # Get rid of b' at start and ' at end 

    chunks = s.split("\\")
    s = bytes(chunks[0], 'ascii')

    skip_next_chunk = False
    for chunk in chunks[1:]:
        if skip_next_chunk:
            s += bytes(chunk, 'ascii')
            skip_next_chunk = False
        elif len(chunk) == 0:
            s += b'\\'
            skip_next_chunk = True
        elif chunk[0] == 'x':
            s += bytes.fromhex(chunk[1:3])
            s += bytes(chunk[3:], 'ascii')
        elif chunk[0] == 't':
            s += b'\t'
            s += bytes(chunk[1:], 'ascii')
        elif chunk[0] == 'n':
            s += b'\n'
            s += bytes(chunk[1:], 'ascii')
        elif chunk[0] == 'r':
            s += b'\r'
            s += bytes(chunk[1:], 'ascii')
        else:
            s += bytes(chunk, 'ascii') 

    return s