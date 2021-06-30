def no_padding(message: bytes, block_size: int) -> bytes:
    """
    Returns the original message if it's length is a multiple of block_size. 
    Otherwise raises an exception.
    """
    if (len(message) % block_size != 0):
        raise ValueError(f"Message length must be a multiple of {block_size}. Got {len(message)}.")
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
        raise ValueError(f"Message length must be a multiple of {block_size}. Got {len(message)}.")
    
    if not is_valid_pkcs7(message):
        raise ValueError("Message has incorrect padding.")
    return message[:-message[-1]]

def is_valid_pkcs7(message: bytes) -> bool:
    pad_value = message[-1]
    return all([x == pad_value for x in message[-pad_value:]])

class Padder:
    """
    Adds and strips padding from byte strings according to the specified mode.
    """
    modes = {
        "nopadding": (no_padding, no_padding),
        "pkcs7": (pkcs7, strip_pkcs7)
    }
    def __init__(self, mode: str, block_size: int):
        add_pad, strip_pad = self.modes[mode.lower()]
        self.block_size = block_size
        self.pad = lambda message: add_pad(message, self.block_size)
        self.strip = lambda message: strip_pad(message, self.block_size)