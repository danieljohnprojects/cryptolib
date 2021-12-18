import pytest
import random

from cryptolib.cracks.rngs import exhaust_seed, replicate_MT19937_state
from cryptolib.rngs import MT19937

random.seed(0)

def test_exhaust_seed():
    seed = 2**10
    rng = MT19937(seed)
    target = rng.rand()
    
    x = exhaust_seed(target)
    assert x == seed

def test_replicate_MT19937_state():
    example_state = [random.randint(0,2**32-1) for _ in range(624)]
    def MTgenerate(x: int) -> int:
        U=11;D=0xffffffff;S=7;B=0x9d2c5680;T=15;C=0xefc60000;L=18
        x ^= (x>>U)&D
        x ^= (x<<S)&B
        x ^= (x<<T)&C
        x ^= x>>L
        return x
    example_output = list(map(MTgenerate, example_state))
    
    test_replicate = replicate_MT19937_state(example_output)
    test = [ex == te for ex,te in zip(example_state, test_replicate)]
    assert all(test)
