import pytest

from cryptolib.cracks.rngs import exhaust_seed
from cryptolib.rngs import MT19937

def test_exhaust_seed():
    seed = 2**10
    rng = MT19937(seed)
    target = rng.rand()
    
    x = exhaust_seed(target)
    assert x == seed
