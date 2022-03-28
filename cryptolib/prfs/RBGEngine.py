from abc import ABC, abstractmethod

class RBGEngine(ABC):
    """
    An abstract class for random byte generators.

    The RBG should be initialised with some seed. After this the only interaction should be through the random number functions.
    """
    @abstractmethod
    def __init__(self, seed: bytes):
        pass

    def rand(self) -> bytes:
        """
        Generate a random string of bytes from the current state.
        """
        raise NotImplementedError
