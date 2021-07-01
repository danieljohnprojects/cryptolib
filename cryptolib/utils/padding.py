"""
Functions for adding and removing padding.
"""


def no_padding(message: bytes, block_size: int) -> bytes:
    """
    Returns the original message if it's length is a multiple of block_size. 
    Otherwise raises an exception.
    """
    if (len(message) % block_size != 0):
        raise ValueError(
            f"Message length must be a multiple of {block_size}. Got {len(message)}.")
    return message


def pkcs7(message: bytes, block_size: int) -> bytes:
    """
    Pads a message to a multiple of blocksize by appending N, N times. Where N is the smallest number that lets you do that.
    """
    assert(block_size < 256 and block_size > 0)
    to_add = block_size - (len(message) % block_size)
    return message + bytes([to_add]*to_add)


def strip_pkcs7(message: bytes, block_size: int) -> bytes:
    """
    Removes pkcs7 padding from a message of bytes.
    """
    assert(block_size < 256 and block_size > 0)
    if (len(message) % block_size != 0):
        raise ValueError(
            f"Message length must be a multiple of {block_size}. Got {len(message)}.")

    if not is_valid_pkcs7(message):
        raise PaddingError()
    return message[:-message[-1]]


def is_valid_pkcs7(message: bytes) -> bool:
    pad_value = message[-1]
    return all([x == pad_value for x in message[-pad_value:]])


class PaddingError(ValueError):
    def __init__(self, *args: object) -> None:
        super().__init__("Provided message has incorrect padding", *args)
