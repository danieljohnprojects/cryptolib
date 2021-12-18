from ..pipes import RandomBytes

def exhaust_seed(
        target_output: bytes,
        rng_type: str='MT19937',
        guess: int = 0,
        guess_high: int = None,
        offset: int = 0,
    ) -> int:
    """
    Takes a target string of bytes and searches for a seed for which the output of the specified RNG matches the target.

    This is a simple exhaust over all possible seeds. If an approximate seed is known (for example if the RNG was seeded with the system time) a starting guess can be passed in. 

    Runtime is linearly proportional to the difference between the estimated and actual seed. A more accurate estimate will mean shorter runtime. That being said for the MT19937 RNG it is very feasible to test all values since the unix epoch on a desktop computer.

    By default the target output is compared to the first bytes outputted by the RNG. This can be changed using the offset argument. For example if it was believed that the target output were bytes 6-10 of the output stream of the RNG you would use offset=6.

    Inputs:
        The output of the RNG.
        The type of RNG.
        Seed estimate.
        Range.
        The output stream offset.

    Output:
    The seed value that produces matching output or None if no seed was found in the required range.
    """

    output_len = len(target_output)

    # Pipe performs value checking offset
    pipe = RandomBytes(rng_type, output_len, offset) 

    max_int = (2**8)**pipe.state['seed_length'] - 1

    if not guess_high:
        guess_high = max_int

    if guess_high > max_int:
        raise ValueError(f"guess_range has exceeded maximum for the specified rng. Got {guess_high} but maximum is {max_int}.")

    # Could parallelise this for loop if you wanted.
    for seed in range(guess, guess_high):
        seed = seed.to_bytes(pipe.state['seed_length'], 'big')
        if pipe(seed) == target_output:
            return int.from_bytes(seed, 'big')
    else:
        raise RuntimeError("No seed found in the given range.")