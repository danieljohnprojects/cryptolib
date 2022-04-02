import pytest
import random

from cryptolib.utils.byteops import reconstruct_from_str

def test_reconstruct_from_str():
    rng = random.Random(12345)
    
    # Try some tricky ones first
    for c in [b'\\', b'\\\'', b'\\\\', b'\\\\j', b'\x00"\'']:
        s = str(c)
        assert reconstruct_from_str(s) == c
    
    # Check all single byte strings
    for i in range(256):
        c = bytes([i])
        s = str(c)
        assert reconstruct_from_str(s) == c
    
    for a in range(256):
        for b in range(256):
            c = bytes([a,b])
            s = str(c)
            assert(reconstruct_from_str(s)) == c

    # Check all 3 byte strings
    # for a in range(256):
    #     for b in range(256):
    #         for c in range(256):
    #             c = bytes([a,b,c])
    #             s = str(c)
    #             assert reconstruct_from_str(s) == c

    for i in range(100):
        message = rng.randbytes(200)
        errormessage = str(message)
        reconstructed_message = reconstruct_from_str(errormessage)
        assert reconstructed_message == message
