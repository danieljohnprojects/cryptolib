def no_padding(message: bytes, block_size: int) -> bytes:
    """
    Returns the original message if it's length is a multiple of block_size. 
    Otherwise raises an exception.
    """
    if (len(message) % block_size != 0):
        raise ValueError(f"Message length must be a multiple of {block_size}. Got {len(message)}.")
    return message