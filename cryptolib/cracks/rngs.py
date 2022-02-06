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

def replicate_MT19937_state(output):
    """
    Replicates the internal state of a Mersenne twister RNG using the first 624 32-bit outputs.

    The input to this function should be a sequence of 624 4-byte integers coming from an MT19937 rng. This function will only work if the RNG does not "twist" at any time during the output.
    """
    assert len(output) == 624
    assert all(x >= 0 for x in output)
    assert all(x < 2**32 for x in output)

    undo4 = lambda x: x^(x>>18)
    state3 = list(map(undo4, output)) # Undo y=y^(y>>L)

    def undo3(x):
        a = x&0x1ffff
        b = ((a>>1)&0xefc6)>>1
        return (((x>>17) ^ b) << 17) ^ a

    # state2 = list(map(lambda x: (((x>>17) ^ ((((x&0x1ffff)>>1)&0xefc6)>>1)) << 17) ^ (x&0x1ffff), state3)) # Undo y ^= (y<<T) & C
    state2 = list(map(undo3, state3))
    
    B = 0x9D2C5680

    def undo2(x):
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
    # state1 = list(map(lambda x: (x&0x7f) ^ # bits [25..31]
    #                       (((x&0x7f)<<7)&B) ^ (x&0x3f80) ^ # bits [18..24]
    #                       ((( ((((x&0x7f)<<7)&B) ^ (x&0x3f80)) <<7)&B) ^ (x&0x1fc000)) ^ # bits [11..17]
    #                       ((( (((((((x&0x7f)<<7)&B)^(x&0x3f80))<<7)&B)^(x&0x1fc000)) <<7)&B) ^ (x & 0xfe00000)) ^ # bits [4..10]
    #                       ( (((((((((((((x&0x7f)<<7)&B)^(x&0x3f80))<<7)&B)^(x&0x1fc000))<<7)&B)^(x&0xfe00000)) & 0x01e00000) <<7)&B) ^ (x & 0xf0000000)), # bits [0..3]
    #             state2))

    state1 = list(map(undo2, state2))
    
    U = 11
    def undo1(x):
        a = x>>21
        b = ((x>>10)&0x7ff) ^ a
        c = (x&0x3ff) ^ (b>>1)
        return (a<<21) ^ (b<<10) ^ c
    state = list(map(undo1, state1))

    # return list(zip(state, state1, state2, state3, output))
    return state