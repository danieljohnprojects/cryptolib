from math import ceil

from .Pipe import Pipe

# from ..rngs import RNG_generators

class RandomBytes(Pipe):
    """
    A pipe that takes in a seed and produces a pre-configured number of random bytes.

    The bytes are produced using the specified pseudo-rng.
    """

    def __init__(self,
                 rng_generator: callable,
                 output_length: int,
                 offset: int = 0,
                 **kwargs):
        """
        Arguments:
            algorithm - the rng algorithm used to produce the bytes
            output_length - the number of bytes to produce
            offset - the byte offset to begin producing bytes at
        """
        # if algorithm.lower() not in RNG_generators:
        #     raise ValueError(f"Algorithm {algorithm} not supported. Must be one of {list(RNG_generators.keys())}")

        # engine_generator = RNG_generators[algorithm.lower()]

        if output_length < 1:
            raise ValueError(f"Output length must be positive. Got {output_length}.")
        if offset < 0:
            raise ValueError(f"Offset must be non-negative. Got {offset}.")

        # Determine how many calls to the rng are needed
        total_calls = ceil(offset + output_length / rng_generator.int_length)

        kwargs['rng_generator'] = rng_generator
        kwargs['total_calls'] = total_calls
        kwargs['output_length'] = output_length
        kwargs['offset'] = offset

        super().__init__(**kwargs)


    def __call__(self, seed: bytes) -> list[int]:
        seed = int.from_bytes(seed, 'little')
        rng = self.state['rng_generator'](seed)
        generated = b''
        for _ in range(self.state['total_calls']):
            x = rng.rand()
            generated += x.to_bytes(rng.int_length, 'little')
        
        return generated[self.state['offset']: self.state['offset'] + self.state['output_length']]
        