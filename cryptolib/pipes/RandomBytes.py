from math import ceil

from .Pipe import Pipe

from ..rngs import RNG_generators

class RandomBytes(Pipe):
    """
    A pipe that takes in a seed and produces a pre-configured number of random bytes.

    The bytes are produced using the specified pseudo-rng.
    """

    def __init__(self,
                 algorithm: str,
                 output_length: int,
                 offset: int = 0,
                 **kwargs):
        
        if algorithm.lower() not in RNG_generators:
            raise ValueError(f"Algorithm {algorithm} not supported. Must be one of {list(RNG_generators.keys())}")

        engine_generator = RNG_generators[algorithm.lower()]
        seed_length = engine_generator.seed_length

        if output_length < 1:
            raise ValueError(f"Output length must be positive. Got {output_length}.")
        if offset < 0:
            raise ValueError(f"Offset must be non-negative. Got {offset}.")

        # Determine how many blocks in total are needed
        total_blocks = ceil(offset + output_length / engine_generator.output_length)

        kwargs['engine_generator'] = engine_generator
        kwargs['seed_length'] = seed_length
        kwargs['total_blocks'] = total_blocks
        kwargs['output_length'] = output_length
        kwargs['offset'] = offset

        super().__init__(**kwargs)


    def __call__(self, seed: bytes) -> bytes:

        rng = self.state['engine_generator'](seed)
        generated = b''
        for _ in range(self.state['total_blocks']):
            generated += rng.rand()
        
        return generated[self.state['offset']: self.state['offset'] + self.state['output_length']]
        