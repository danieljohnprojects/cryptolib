import pytest
import random

from  cryptolib.pipes import RandomBytes

def test_RandomBytes():

    # We are only testing the offset and length parts here.
    # Assume that the RNG is sound based on other tests.

    # Lengths and offsets to check:
    los = [
        (3,1),  # Single call with one byte discarded from the start.
        (3,0),  # Single call with one byte discarded from the end.
        (2,1),  # Single call with one byte discarded from each end.
        (7,1),  # Two calls with a single byte discarded from the start.
        (7,1),  # Two calls with a single byte discarded from the end.
        (6,1),  # Two calls with a single byte discarded from each end.
        (4,2),  # Two calls with two bytes discarded from each end.
        (2,3),  # Two calls with three bytes discarded from each end.
        (3,5),  # Two calls with a full block plus a single byte discarded from the start.
        (6,5)   # Three calls with a full block discarded from the start plus a single byte discarded from each end.
    ]

    rng = random.Random(0)
    for _ in range(5):
        seed = rng.randbytes(4)

        # First test just the length with no offset
        pipe = RandomBytes("mt19937", 20, 0)
        out = pipe(seed)
        for length, offset in los:
            pipe = RandomBytes("mt19937", length, offset)
            test = pipe(seed)
            assert test == out[offset:offset+length], f"test of length: {length}, offset: {offset}"
