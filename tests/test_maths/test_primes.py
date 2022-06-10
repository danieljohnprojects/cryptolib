import pytest
import random
from cryptolib.maths.primes import factorise, fermat_test, generatePrime, miller_rabin_test

def test_fermat_test():
    seed = 12345
    primes = [
        2,3,5,7,11,13,17,19,23,29,31,37,41,8191,999999000001,
        0x9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e374171fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa871033,
        0xd4bcd52406f69b35994b88de5db89682c8157f62d8f33633ee5772f11f05ab22d6b5145b9f241e5acc31ff090a4bc71148976f76795094e71e7903529f5a824b
    ]
    for p in primes:
        assert fermat_test(p, seed=seed)
    for p in primes[1:]:
        assert not fermat_test(p+1, seed=seed)
    for p in set(range(2, 41)).difference(primes):
        assert not fermat_test(p, seed=seed)
    # Doesn't work on "Carmichael numbers"
    p = 84350561
    assert p == 107*743*1061 # Note that f-1 divides p-1 for all factors f.
    assert fermat_test(p, seed=seed) # Passes primality test despite being composite.
    
def test_miller_rabin_test():
    seed = 12345
    primes = [
        2,3,5,7,11,13,17,19,23,29,31,37,41,8191,999999000001,
        0x9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e374171fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa871033,
        0xd4bcd52406f69b35994b88de5db89682c8157f62d8f33633ee5772f11f05ab22d6b5145b9f241e5acc31ff090a4bc71148976f76795094e71e7903529f5a824b
    ]
    for p in primes:
        assert miller_rabin_test(p, seed=seed)
    for p in primes[1:]:
        assert not miller_rabin_test(p+1, seed=seed)
    for p in set(range(2, 41)).difference(primes):
        assert not miller_rabin_test(p, seed=seed)
        
    #TODO Find a composite that fools the Miller-Rabin test.
    
def test_factorise():
    # seed = 12345
    # p = generatePrime(128, seed=seed)
    p = 340484563128503304223833324170966481637
    assert factorise(p-1) == [2,2,3,7,11,19,3413,9029,629355327997567858704696253]
    assert factorise(p+1) == [2, 13, 37, 211, 487, 4783, 358441, 6576833369, 305475256601]
    # seed = 1234
    # p = generatePrime(128, seed=seed)
    p = 327435217573504622653930443244843925453
    assert factorise(p-2) == [3, 3049, 35797006403575447977908652371798833]
    assert factorise(p+1) == [2, 3, 2592683963, 4678296053, 4499216122741530331]