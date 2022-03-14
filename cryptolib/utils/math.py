from functools import reduce
from math import gcd, comb

def xgcd(a: int,b: int) -> int:
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

def Legendre_symbol(x: int, p: int) -> int:
    """
    Calculate the Legendre symbol of x with respect to a prime p.

    The answer will be 1 if x is congruent to a perfect square modulo p, 0 if x is congruent to 0 modulo p, and -1 otherwise.

    Does not check that p is prime.
    """
    return pow(x, (p-1)//2, p)

def square_root_modulo(x: int, p: int) -> int:
    """
    Computes the square root of x modulo a prime p. Currently only works if p is congruent to 3 mod 4.

    Does not check that p is prime.
    """
    assert p%4 == 3
    return pow(x, (p+1)//4, p)

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
    x = sum([x*r for x,r in zip(xs, remainders)])
    return x%prod

def numberToBase(n: int, b: int) -> list[int]:
    """
    Computes the digits of n in base b and stores them in a list.
    """
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]

def encode_as_combination(x: int, n: int, k: int) -> str:
    """
    Encodes the number x as a binary vector of length n with exactly k 1s.
    """
    if x < 0:
        raise ValueError(f"Argument x must be between 0 and n-1 inclusive. Got {x}.")
    elif x >= comb(n, k):
        raise ValueError(f"Argument x must be between 0 and comb(n,k)-1 inclusive. Got {x} (>= comb({n},{k}) = {comb(n,k)}).")
    if k < 0:
        raise ValueError(f"Argument x must be between 0 and n inclusive. Got {k}.")
    elif k > n:
        raise ValueError(f"Argument x must be between 0 and n inclusive. Got {k} (> {n}).")

    encoding = []
    while k in range(1,n):
        if x >= (c := comb(n-1, k)):
            x -= c
            n -= 1
            k -= 1
            encoding.append(1)
        else:
            n -= 1
            encoding.append(0)
    if k == 0:
        encoding += n*[0]
    elif k == n:
        encoding += n*[1]
    return ''.join([str(x) for x in encoding])

def decode_combination(combination: str) -> int:
    n, k, x = 0, 0, 0
    remaining1s = combination.count('1')
    remaining0s = combination.count('0')
    if remaining0s == 0 or remaining1s == 0:
        return 0
    while combination and remaining1s:
        if (combination[-1] == '1'):
            remaining1s -= 1
            k += 1
            n += 1
            x += comb(n-1, k)
        elif combination[-1] == '0':
            remaining0s -= 1
            n += 1
        else:
            raise ValueError("Argument combination must consist only of 0s and 1s")
        combination = combination[:-1]
    return x
        