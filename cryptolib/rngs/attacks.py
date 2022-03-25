from functools import reduce
from typing import Sequence

from ..pipes import RandomBytes
from ..rngs import MT19937, RNG_generators


def exhaust_seed(
        target_output: Sequence[int],
        rng_type: str='MT19937',
        guess_low: int = 0,
        guess_high: int = None,
        offset: int = 0,
    ) -> int:
    """
    Takes a target sequence of integers and searches for a seed for which the output of the specified RNG matches the target.

    This is a simple exhaust over all possible seeds. If an approximate seed is known (for example if the RNG was seeded with the system time) a starting guess can be passed in. 

    Runtime is linearly proportional to the difference between the estimated and actual seed. A more accurate estimate will mean shorter runtime. That being said for the MT19937 RNG it is very feasible to test all values since the unix epoch on a desktop computer.

    By default the target output is compared to the first bytes outputted by the RNG. This can be changed using the offset argument. For example if it was believed that the target output were bytes 6-10 of the output stream of the RNG you would use offset=6.

    Args:
        target_output: A sequenc eof integers that is the suspected output of an RNG.
        rng_type: The name of the RNG suspected to have produced the ouptut.
        guess_low: A lower bound on the seed.
        guess_high: An upper bound on the seed.
        offset: The output stream offset.
    Returns:
        The seed value that produces matching output.
    Raises:
        ValueError: If the rng_type is not recognised, or if the bounds on the seed exceed the allowed seed values for the specified rng.
        RuntimeError: If no seed was found producing the targetted output.
    """

    if rng_type.lower() not in RNG_generators:
        raise ValueError(f"Algorithm {rng_type} not supported. Must be one of {list(RNG_generators.keys())}")

    rng_generator = RNG_generators[rng_type.lower()]

    if (guess_low < 0) or (guess_low > rng_generator.max_int):
        raise ValueError(f"Lower bound on guess must be between 0 and {rng_generator.max_int}. Got {guess_low}.")

    if guess_high is None:
        guess_high = rng_generator.max_int
    elif (guess_high < 1) or (guess_high > rng_generator.max_int):
        raise ValueError(f"Upper bound on guess must be between 0 and {rng_generator.max_int}. Got {guess_high}.")

    byte_length = rng_generator.int_length * len(target_output)
    # Pipe performs value checking of offset
    pipe = RandomBytes(rng_generator, byte_length, offset) 

    target_output = map(lambda x: int.to_bytes(x, rng_generator.int_length, 'little'), target_output)
    target_output = reduce(bytes.__add__, target_output)

    # Could parallelise this for loop if you wanted.
    # Would probably need independent pipes.
    for seed in range(guess_low, guess_high):
        seed = seed.to_bytes(rng_generator.int_length, 'little')
        if pipe(seed) == target_output:
            return int.from_bytes(seed, 'little')
    else:
        raise RuntimeError("No seed found in the given range.")


