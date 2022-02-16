import pytest
import random

from cryptolib.cracks.rngs import exhaust_seed, replicate_MT19937_state, revert_to_state
from cryptolib.rngs import MT19937

random.seed(0)

def test_exhaust_seed():
    seed = 2**10
    rng = MT19937(seed)
    target = rng.rand()
    
    x = exhaust_seed(target)
    assert x == seed

def test_replicate_MT19937_state():
    # # example_state = [random.randint(0,2**32-1) for _ in range(624)]
    # example_state = [random.randbytes(MT19937.state_element_length) for _ in range(MT19937.state_array_length)]
    # rng = MT19937(example_state)
    # for s in example_state:
    #     assert revert_to_state(rng.rand()) == s
    
    # # # def MTgenerate(x: int) -> tuple:
    # def MTgenerate(x: int) -> int:
    #     U=11;D=0xffffffff;S=7;B=0x9d2c5680;T=15;C=0xefc60000;L=18
    #     y1 = x ^ ((x>>U)&D)
    #     y2 = y1 ^ ((y1<<S)&B)
    #     y3 = y2 ^ ((y2<<T)&C)
    #     z  = y3 ^ (y3>>L)
    #     # return z
    #     return x, y1, y2, y3, z
    # # example_output = list(map(MTgenerate, example_state))
    # # attack_input = [x[-1] for x in example_output]
    # example_output = [MTgenerate(x) for x in example_state]

    # # test_replicate = replicate_MT19937_state(attack_input)
    # test_replicate = replicate_MT19937_state(example_output)
    # test = [ex == te for ex,te in zip(example_state, test_replicate)]
    # assert all(test)

    pyrng = random.Random(0)
    for _ in range(MT19937.state_array_length * 4):
        pyrng.getrandbits(MT19937.int_length * 8)

    output = [pyrng.getrandbits(MT19937.int_length * 8) for _ in range(624)]
    cloned_rng = replicate_MT19937_state(output)

    for _ in range(10000):
        assert pyrng.getrandbits(MT19937.int_length * 8) == cloned_rng.rand()

