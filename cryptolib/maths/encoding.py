"""
Functions for encoding numbers in funny ways.
"""

from math import comb

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
        