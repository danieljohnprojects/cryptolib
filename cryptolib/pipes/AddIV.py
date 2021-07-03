from random import Random
from .Pipe import Pipe

class AddIV(Pipe):
    """
    Generates a new random IV that is prepended to the front of each message.
    
    For example this pipe might form the first component of a CBC encryption oracle so that a new IV is used for each message.
    """
    def __init__(self, block_size: int = 16, seed=None, **kwargs):
        kwargs['block_size'] = block_size
        kwargs['random'] = Random(seed)
        super().__init__(**kwargs)
    
    def __call__(self, message: bytes) -> bytes:
        iv = self.state['random'].randbytes(self.state['block_size']) 
        return iv + message