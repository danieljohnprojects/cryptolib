from secrets import token_bytes
from ..oracles import Oracle

class GenIV(Oracle):
    """
    Generates an IV that is passed to the parent oracle each time a message flows through the pipe.
    
    For example this pipe might form the first component of a CBC encryption oracle so that a new IV is used for each message.
    """
    def __init__(self, block_size: int = 16):
        self.block_size = block_size
    
    def __call__(self, message: bytes) -> bytes:
        self.parent.iv = token_bytes(self.block_size)
        return message