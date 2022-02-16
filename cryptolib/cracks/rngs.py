from functools import reduce
from typing import Sequence

from ..pipes import RandomBytes
from ..rngs import MT19937, RNG_generators


def exhaust_seed(
        target_output: Sequence[int], #bytes,
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

    Inputs:
        The output of the RNG.
        The type of RNG.
        A lower bound on the seed.
        An upper bound on the seed.
        The output stream offset.

    Output:
    The seed value that produces matching output or None if no seed was found in the required range.
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


def revert_to_state(output: int) -> int:
    """
    Takes a 4-byte integer output of a Mersenne twister rng and pulls it back through the generation process to reveal the state element from which it was originally generated.
    """
    assert (output >= 0) and (output < MT19937.max_int)
    # assert isinstance(output, bytes)
    # int_output = int.from_bytes(output, 'big')

    # Define functions to undo each step of the MT19937 generation process
    undo4 = lambda x: x^(x>>18)
    def undo3(x):
        a = x&0x1ffff
        b = ((a>>1)&0xefc6)>>1
        return (((x>>17) ^ b) << 17) ^ a
    def undo2(x):
        B = 0x9D2C5680
        
        a = x&0x7f          # bits [25..31]
        b = x&0x3f80
        c = ((a<<7)&B) ^ b  # bits [18..24]
        d = (x&0x1fc000)
        e = ((c<<7)&B) ^ d  # bits [11..17]
        f = (x & 0xfe00000)
        g = ((e<<7)&B) ^ f  # bits [4..10]
        h = (x & 0xf0000000)
        i = ((g<<7)&B) ^ h  # bits [0..3]
        return i ^ g ^ e ^ c ^ a
    def undo1(x):
        a = x>>21
        b = ((x>>10)&0x7ff) ^ a
        c = (x&0x3ff) ^ (b>>1)
        return (a<<21) ^ (b<<10) ^ c

    # Apply the functions to the output to recover the state
    state3 = undo4(output)
    state2 = undo3(state3)
    state1 = undo2(state2)
    state = undo1(state1)

    # byte_state = int.to_bytes(state, MT19937.state_element_length, 'big')

    return state
    # return state, state1, state2, state3, int_output


def replicate_MT19937_state(output: Sequence[int]) -> MT19937:
    """
    Takes the first 624 outputs from a Mersenne twister RNG and constructs a replica of the RNG that generated the output.

    The input to this function should be a sequence of 624 4-byte integers coming from an MT19937 rng. This function will only work if the RNG does not "twist" at any time during the output for example the first 624 outputs of the target RNG can be used.

    The output of the function is an RNG object capable of continuing to generate the same sequence of bytes.
    """
    assert len(output) == MT19937.state_array_length
    assert all(isinstance(x, int) for x in output)
    assert all((x >= 0) and (x < MT19937.max_int)  for x in output)

    state = list(map(revert_to_state, output))

    clone = MT19937(state)
    return clone