import pytest
from cryptolib.maths.primes import fermat_test

def test_fermat_test():
    primes = [2,3,5,7,11,13,17,19,23,29,31,37,41]
    for p in primes:
        assert fermat_test(p)
    for p in set(range(2, 41)).difference(primes):
        assert not fermat_test(p)