from ctypes import *
from typing import Union
from .RNG import RNGEngine
from ..utils.files import build_filename

class MT19937(RNGEngine):
    """
    Generates random numbers according to the 32-bit implementation of the Mersenne twister algorithm.

    The generator is initialised with four byte seed and generates outputs four bytes at a time.
    """
    
    # Length in bytes of seed and output
    seed_length = 4
    max_seed = (2**8)**seed_length
    output_length = 4

    def __init__(self, seed: Union[int, bytes]):
        # Check the seed value
        if isinstance(seed, int):
            if (seed < 0) or (seed >= self.max_seed):
                raise ValueError(f"Seed must be a positive integer that can be represented by a {self.seed_length} byte unsigned int (got {seed}).")
        elif isinstance(seed, bytes):
            if len(seed) != self.seed_length: # This could be a < rather than != but I like being specific.
                raise ValueError(f"Seed must be {self.seed_length} bytes long, got {len(seed)}.")
            seed = int.from_bytes(seed, 'big')
        else:
            raise ValueError(f"Seed must either be an int or bytes object, got {type(seed)}.")
        seed = c_uint(seed)
        
        # Import the C functions for the Mersenne Twister
        libpath = build_filename('build/MersenneTwister/libMT19937.so')
        self._MTlibC = CDLL(libpath)
        # Set the proper types for the functions
        self._MTlibC.set_seed.argtypes = [c_uint32, c_char_p]
        self._MTlibC.extract32.restype = c_uint

        self._N = 624
        state_len = 4 * self._N
        self._state = create_string_buffer(state_len)

        self._MTlibC.set_seed(seed, self._state)
        self._index = 0

    def rand(self) -> bytes:
        if self._index % self._N == 0:
            self._MTlibC.twist(self._state)
        generated = self._MTlibC.extract32(self._state, self._index)
        self._index = (self._index + 1) % self._N
        return generated.to_bytes(4, 'big')
