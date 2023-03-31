from functools import reduce
from math import gcd
from typing import Tuple


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Computes the gcd of a and b along with numbers x and y such that xa+yb=gcd(a,b).
    """
    old_r, r = max(a, b), min(a, b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q*r
        old_s, s = s, old_s - q*s
        old_t, t = t, old_t - q*t
    if a < b:
        old_s, old_t = old_t, old_s
    assert a*old_s + b*old_t == old_r
    return old_r, old_s, old_t


def CRT(remainders: list[int], moduli: list[int]) -> int:
    """
    Given a list of remainders and a list of moduli (all of which are coprime), computes a number which satisfies the congruences:
    x = r1 (mod m1)
    x = r2 (mod m2)
    ...
    x = rn (mod mn)
    where remainders = [r1, ..., rn] and moduli = [m1, ..., mn].
    """
    assert gcd(*moduli) == 1
    prod = reduce(int.__mul__, moduli)
    xs = [xgcd(m, prod//m)[2] * (prod//m) for m in moduli]
    x = sum([x*r for x, r in zip(xs, remainders)])
    return x % prod


def Legendre_symbol(x: int, p: int) -> int:
    """
    Calculate the Legendre symbol of x with respect to a prime p.

    The answer will be 1 if x is congruent to a perfect square modulo p, 0 if x is congruent to 0 modulo p, and -1 otherwise.

    Does not check that p is prime.
    """
    return pow(x, (p-1)//2, p)


def sqrt_modulo(x: int, p: int) -> int:
    """
    Computes the square root of x modulo a prime p. Currently only works if p is congruent to 3 mod 4.

    Tonelli-Shanks algorithm

    Does not check that p is prime.
    """
    assert Legendre_symbol(x, p) == 1

    if p % 4 == 3:
        return pow(x, (p+1)//4, p)

    # Write p = q2^s + 1
    q = p - 1
    s = 0
    while not q % 2:
        s += 1
        q = q//2

    # Find z in Z_p which is a quadractic non-residue
    z = 2
    while Legendre_symbol(z, p) == 1:
        z = (z + 1) % p

    M = s
    c = z**q
    t = x**q
    R = x**((q+1)//2)

    raise NotImplementedError
