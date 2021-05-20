"""
Operations on byte objects.
"""

def block_xor(b1: bytes, b2: bytes) -> bytes:
    """
    Xors two byte objects of the same length together.
    """
    if len(b1) != len(b2):
        raise ValueError("Blocks must be of the same length.")
    return bytes([x^y for x,y in zip(b1, b2)])

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

def hamming_distance(m1: bytes, m2:bytes) -> int:
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