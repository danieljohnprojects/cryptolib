from abc import ABC, abstractmethod

class RNGEngine(ABC):
    """
    An abstract class for random number generators.

    The RNG should be initialised with some seed. After this the only interaction should be through the random number functions.
    """
    @abstractmethod
    def __init__(self, seed: int):
        pass

    def rand(self) -> int:
        """
        Generate a random integer from the current state.
        """
        raise NotImplementedError
