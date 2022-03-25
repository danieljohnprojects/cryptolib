from ctypes import *
from functools import reduce
from typing import Sequence, Union
from .RNG import RNGEngine
from ...utils.files import build_filename

class MT19937(RNGEngine):
    """
    Generates random numbers according to the 32-bit implementation of the Mersenne twister algorithm.

    The generator can be initialised in two separate ways. The first being with a non-negative integer less than 2**32. The second way is to pass an array of integers less than 2**32 that will make up the internal state of the rng.

    If initialised using the second method the rng will twist the state during the first call to the rand method, before generating any bytes. So the first bytes generated will not be directly derived from the first element of the state.
    
    An MT19937 object generates pseudo-random integers using the rand function.
    """
    int_length = 4      # Length of integers in bytes
    max_int = (2**8)**int_length
    state_array_length = 624    # Number of elements in the state array

    # Import the C functions for the Mersenne Twister
    libpath = build_filename('build/MersenneTwister/libMT19937.so')
    _MTlibC = CDLL(libpath)
    # Set the proper types for the functions
    _StateArrayType = c_uint32 * state_array_length
    _MTlibC.set_seed.argtypes = [c_uint32, _StateArrayType]
    _MTlibC.extract32.restype = c_uint32


    def __init__(self, seed: Union[int, Sequence[int]], index: int=0):
        # Check the seed value
        if isinstance(seed, int):
            if (seed < 0) or (seed >= self.max_int):
                raise ValueError(f"Seed must be a positive integer that can be represented by a {self.int_length} byte unsigned int (got {seed}).")
        elif isinstance(seed, Sequence):
            if (len(seed) != self.state_array_length):
                raise ValueError(f"In order to set internal state a list of length {self.state_array_length} must be passed. Got a list of length {len(seed)}.")
            isint = [isinstance(x, int) for x in seed]
            if not all(isint):
                offending_index = isint.index(False)
                raise TypeError(f"In order to set internal state all objects in list must be integers. Found an object of type {type(seed[offending_index])} at index {offending_index}.")
            isinrange = [(x >= 0) and (x < self.max_int) for x in seed]
            if not all(isinrange):
                offending_index = isinrange.index(False)
                raise ValueError(f"In order to set internal state all integers in the list need to be between 0 and {self.max_int}. Element at index {offending_index} has value {seed[offending_index]}.")
        else:
            raise TypeError(f"Seed must either be an int or sequence of ints, got {type(seed)}.")
        
        self._state = self._StateArrayType()

        if isinstance(seed, Sequence):
            for i, state_element in enumerate(seed):
                self._state[i] = c_uint32(state_element)
            if index not in range(0,self.state_array_length):
                raise ValueError(f"Index must be between 0 and {self.state_array_length}. Got {index}.")
            self._index = index
        else:
            self._MTlibC.set_seed(c_uint32(seed), self._state)
            if index != 0:
                raise ValueError("Index can only be set when initialising state.")
            self._index = 0
        

    def rand(self) -> int:
        if self._index % self.state_array_length == 0:
            self._MTlibC.twist(self._state)
        generated = self._MTlibC.extract32(self._state, self._index)
        self._index = (self._index + 1) % self.state_array_length
        return generated
