import pytest
from cryptolib.maths.math import xgcd

def test_xgcd():
    gcd, x, y = xgcd(48, 69)
    assert(gcd == 3)
    assert(x*48 + y*69 == gcd)
    gcd, x, y = xgcd(69, 48)
    assert(gcd == 3)
    assert(x*69 + y*48 == gcd)
