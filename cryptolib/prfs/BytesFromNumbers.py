from . import RNG_generators

class BytesFromNumbers:
    """
    Instantiate a pseudo-random byte generator out of a pseudo-random number generator.
    """
    def __init__(self, rng: str, seed: bytes, endianness: str = 'little'):
        engine_constructor = RNG_generators[rng]
        int_seed = int.from_bytes(seed, endianness, signed=False)
        self.engine = engine_constructor(int_seed)
        self.endianness = endianness
        self.output_length = self.engine.int_length

    def rand(self) -> bytes:
        return self.engine.rand().to_bytes(self.output_length, self.endianness)