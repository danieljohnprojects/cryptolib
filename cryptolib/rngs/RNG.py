from abc import ABC, abstractmethod

class RNGEngine(ABC):
    """
    An abstract class for random number generators.

    The RNG should be initialised with some seed. After this the only interaction should be throught the random number functions.
    """
    @abstractmethod
    def __init__(self, seed: bytes):
        pass

    def rand(self) -> bytes:
        """
        Generate a random string of bytes.

        The length of the string is algorithm dependent.
        """
        raise NotImplementedError
