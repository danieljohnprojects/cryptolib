from abc import abstractclassmethod
from .Oracle import Oracle

class BCOracle(Oracle):
    """
    Oracle that takes in a message in bytes, processes it, and encrypts with a block cipher. Then returns the encrypted message in bytes.
    """
    @abstractclassmethod
    def divine(self, message: bytes) -> bytes:
        pass