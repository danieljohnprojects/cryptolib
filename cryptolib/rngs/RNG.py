from abc import ABC, abstractmethod


class RNG(ABC):
    """
    An abstract class for random number generators.

    The RNG should be initialised with some seed. After this the only interaction should be throught the random number functions.
    """
    @abstractmethod
    def __init__(self, seed: bytes):
        pass

    def rand32(self):
        """
        Generates a uniform random string of 32 bits.
        """
        raise NotImplementedError

    def rand64(self):
        """
        Generates a uniform random string of 64 bits.
        """
        raise NotImplementedError