from typing import Sequence

from .algorithms import MT19937


def revert_to_state(output: int) -> int:
    """
    Takes a 4-byte integer output of a Mersenne twister RNG and pulls it back through the generation process to reveal the state element from which it was originally generated.

    Args:
        output: The output of a Mersenne twister RNG
    Returns:
        The value of the state from which the output value was derived.
    Raises:
        ValueError: If the given output value is not a valid Mersenne twister output.
    """
    if (output < 0) or (output >= MT19937.max_int):
        raise ValueError(f"Provided output value must lie between 0 and {MT19937.max_int}. Received {output}.")

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

    # return state, state1, state2, state3, int_output
    return state


def replicate_MT19937_state(output: Sequence[int]) -> MT19937:
    """
    Takes the first 624 outputs from a Mersenne twister RNG and constructs a replica of the RNG that generated the output.

    The input to this function should be a sequence of 624 4-byte integers coming from an MT19937 rng. This function will only work if the RNG does not "twist" at any time during the output for example the first 624 outputs of the target RNG can be used.

    The output of the function is an RNG object capable of continuing to generate the same sequence of bytes.

    Args:
        output: The first 624 output values of a Mersenne twister RNG.
    Returns:
        An RNG object that continues from where the given output finished.
    Raises:
        ValueError: if the provided output stream is not a valid Mersenne twister output stream or if the output stream is of the wrong length.
    """
    if len(output) != MT19937.state_array_length:
        raise ValueError(f"Provided output has incorrect length. Expected {MT19937.state_array_length} values, received {len(output)}.")
    if not all(isinstance(x, int) for x in output):
        raise ValueError(f"Provided output stream must all be of type int.")
    if not all((x >= 0) and (x < MT19937.max_int)  for x in output):
        raise ValueError(f"Provided output must all lie between 0 and {MT19937.max_int}.")

    state = list(map(revert_to_state, output))

    clone = MT19937(state)
    return clone