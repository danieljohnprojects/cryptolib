from ctypes import *
from functools import reduce
from typing import Union
from .RNG import RNGEngine
from ..utils.files import build_filename

class MT19937(RNGEngine):
    """
    Generates random numbers according to the 32-bit implementation of the Mersenne twister algorithm.

    The generator can be initialised in two separate ways. The first being with a four byte seed in the form of a non-negative integer less than 2**32 or in byte form. The second way is to pass an array of bytes that will make up the internal state of the rng.

    If initialised using the second method the rng will twist the state during the first call to the rand method, before generating any bytes. So the first bytes generated will not be directly derived from the first element of the state.
    
    An MT19937 object generates outputs four bytes at a time using the rand function.
    """
    
    seed_length = 4     # Length of seed in bytes
    max_seed = (2**8)**seed_length
    output_length = 4   # Length of output in bytes
    state_array_length = 624    # Number of elements in the state array
    state_element_length = 4    # Length of each element of the state array in bytes

    # Import the C functions for the Mersenne Twister
    libpath = build_filename('build/MersenneTwister/libMT19937.so')
    _MTlibC = CDLL(libpath)
    # Set the proper types for the functions
    _MTlibC.set_seed.argtypes = [c_uint32, c_char_p]
    _MTlibC.extract32.restype = c_uint


    def __init__(self, seed: Union[int, bytes, list[bytes]], index: int=0):
        # Check the seed value
        if isinstance(seed, int):
            if (seed < 0) or (seed >= self.max_seed):
                raise ValueError(f"Seed must be a positive integer that can be represented by a {self.seed_length} byte unsigned int (got {seed}).")
        elif isinstance(seed, bytes):
            if len(seed) != self.seed_length: # This could be a < rather than != but I like being specific.
                raise ValueError(f"Seed must be {self.seed_length} bytes long, got {len(seed)}.")
            seed = int.from_bytes(seed, 'big')
        elif isinstance(seed, list):
            if (len(seed) != self.state_array_length):
                raise ValueError(f"In order to set internal state a list of length {self.state_array_length} must be passed. Got a list of length {len(seed)}.")
            isbytes = [isinstance(x, bytes) for x in seed]
            if not all(isbytes):
                offending_index = isbytes.index(False)
                raise ValueError(f"In order to set internal state all objects in list must be bytes. Found an object of type {type(seed[offending_index])} at index {offending_index}.")
            iscorrectlength = [len(x) == self.state_element_length for x in seed]
            if not all(iscorrectlength):
                offending_index = iscorrectlength.index(False)
                raise ValueError(f"In order to set internal state all bytes objects in the list need to have length {self.state_element_length}. Found an element of length {len(seed[offending_index])} at index {offending_index}.")
        else:
            raise ValueError(f"Seed must either be an int or bytes object, got {type(seed)}.")
        

        state_len = self.state_array_length * self.state_element_length
        self._state = create_string_buffer(state_len)

        if isinstance(seed, list):
            state = reduce(bytes.__add__, seed)
            for i in range(len(state)):
                self._state[i] = c_char(state[i]) # Careful not to change the types of elements
            if index not in range(0,self.state_array_length):
                raise ValueError(f"Index must be between 0 and {self.state_array_length}. Got {index}.")
            self._index = index
        else:
            seed = c_uint(seed)
            self._MTlibC.set_seed(seed, self._state)
            if index != 0:
                raise ValueError("Index can only be set when initialising state.")
            self._index = 0
        

    def rand(self) -> bytes:
        if self._index % self.state_array_length == 0:
            self._MTlibC.twist(self._state)
        generated = self._MTlibC.extract32(self._state, self._index)
        self._index = (self._index + 1) % self.state_array_length
        return generated.to_bytes(self.state_element_length, 'big')
