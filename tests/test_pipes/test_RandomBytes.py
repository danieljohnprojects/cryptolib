import pytest
import random

from  cryptolib.pipes import RandomBytes

def test_RandomBytes():

    # Seeds and test vectors:
    seeds_tvs = [
        (b'\x00\x00\x15q', b'\xd0\x91\xbb\\"\xae\x9e\xf6\xe7\xe1\xfa\xee\xd5\xc3\x1fy \x825,'),
        (1131464071, b"\xd1\xe6\xe2\xf8A\xaf\n\xb5@'\x0f\x88\xaf\xbdJs\xe2\x05\xab\xab")
    ]

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

    for seed, tv in seeds_tvs:
        # First test just the length with no offset
        pipe = RandomBytes("mt19937", 20, 0)
        out = pipe(seed)
        assert out == tv
        for length, offset in los:
            pipe = RandomBytes("mt19937", length, offset)
            test = pipe(seed)
            assert test == out[offset:offset+length], f"test of length: {length}, offset: {offset}"
