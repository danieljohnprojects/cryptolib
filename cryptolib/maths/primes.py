"""
Functions for generating and testing primes.
"""
import random
from math import ceil, floor, gcd, prod
from typing import Optional

from .smallPrimes import primeList

def fermat_test(p: int, samples: int = 100, seed: Optional[int] = None) -> bool:
    """
    Fermat's theorem states that if p is prime then a^(p-1) == 1 (mod p) for every a between 2 and p-1.
    In this function we test a random sample of values for a in the range [2,p-1], if all of these are congruent to 1 we return True otherwise we return False.

    Args:
        p: The candidate prime number.
        samples: The number of a's to test.
        seed: The seed used to generate the a's.
    Returns:
        True if all a^(p-1) = 1 (mod p), False otherwise.
    """
    if p < 1000:
        A = [pow(a, p-1, p) == 1 for a in range(1, p)]
        return all(A)
    rng = random.Random(seed)
    # A = rng.sample(range(2, p), samples) # This doesn't work for very large p
    A = [rng.randint(2, p-1) for _ in range(samples)]
    A = [pow(a, p-1, p) == 1 for a in A]
    return all(A)

def miller_rabin_test(p: int, samples: int = 100, seed: Optional[int] = None) -> bool:
    """
    A number p is prime if and only if the only numbers that square to 1 mod p are 1 and -1. This test
    uses that fact to determine if a number is composite. A number passes the Miller-Rabin test if we 
    do not find a non-trivial square root of 1.

    Args:
        p (int): The candidate prime
        samples (int, optional): The number of samples to perform the test with. Defaults to 100.
        seed (Optional[int], optional): The seed given to the rng. Defaults to None.

    Returns:
        bool: True if p passes the test, False if it is definitely composite.
    """
    assert p > 0
    # Handle annoying edge cases here
    if p == 1:
        return False
    if p == 2:
        return True
    
    q = p-1
    s = 0
    while (q % 2 == 0) and (q > 0):
        s += 1
        q = q // 2
    
    rng = random.Random(seed)
    
    for _ in range(samples):
        a = rng.randint(2, p-1)
        if pow(a, p-1, p) != 1:
            return False
        
        if pow(a, q, p) == 1:
            pass
        else:
            for i in range(s):
                if pow(a, q*2**i, p) == p-1:
                    break # We've found a trivial square-root of 1
            else:
                return False # If we get to the end we have a non-trivial square-root of 1.
    return True

def generatePrime(nBits: float, seed: Optional[int] = None) -> int:
    """
    Generates a number with the specified bit-length that is likely to be a 
    prime. No other properties should be assumed, in particular it may be the 
    case that the prime is not suited for cryptographic applications.
    
    Args:
        nBits (float): The number of bits of the desired number.
        seed (Optional[int]): The seed used to generate the number.
    Returns:
        int: A number which is very likely to be prime and of the desired magnitude.
    """
    if nBits <= 0:
        raise ValueError(f"Argument nBits must be positive. Got {nBits}.")
    rng = random.Random(seed)
    testNum = rng.randint(max(1,floor(2**(nBits-0.1))), ceil(2**(nBits+0.1)))
    while not miller_rabin_test(testNum):
        testNum += 1
    return testNum

def pollardRho(N: int, maxSteps: int = 1000000) -> int:
    """
    Attempts to find factors of N using Pollard's Rho algorithm. The idea of 
    this algorithm is to construct a sequence of numbers (x_k) by iterating the
    following function:
    g(x) = x*x + 1 (mod N).
    Suppose p is a number dividing N. There is an induced sequence (y_k) given 
    by:
    y_k = x_k (mod p)
    that we cannot directly observe.
    Now consider what happens when (y_k) cycles. Suppose y_j = y_k for some j 
    and k. Then x_j - x_k is a multiple of p. In particular, this number shares 
    a factor with N. We can find the common factor by taking the gcd.    

    Args:
        N (int): The number to be factored.
        maxSteps (int, optional): The maximum number of steps taken in the 
            cycle finding process. Defaults to 1000000.

    Returns:
        int: The divisor found by the algorithm.
    """
    g = lambda x: (pow(x, 2, N) + 1) % N
    
    startingPoint = 2
    
    tortoise = startingPoint
    hare = startingPoint
    d = 1
    while d==1 and maxSteps > 0:
        maxSteps -= 1
        tortoise = g(tortoise) # Single step
        hare = g(g(hare)) # Double step
        d = gcd(abs(tortoise-hare), N) # Check for a collision in the induced sequence.
    return d
    
def pollardP_1(N: int) -> int:
    """
    Attempts to find a factor of N using Pollard's p-1 algorithm. Suppose p 
    divides N, then for any a coprime to p we have 
    a^(p-1) = 1 (mod p). 
    In fact for any K we have 
    a^(K*(p-1)) = 1 (mod p).
    Suppose we take M a number with many small prime factors, then if p-1 is 
    small enough it probably divides M. In this case we have
    a^M = 1 (mod p)
    meaning
    p|(a^M - 1).
    Thus a^M - 1 shares a divisor with N, so we can take the gcd to find it.

    Note that this particular implementation will ignore powers of 2 that 
    divide N.

    Args:
        N (int): The number to be factored.

    Returns:
        int: A number that divides N. 
    """
    if not isinstance(N, int):
        raise ValueError(f"N must be a positive integer. Got {N}.")
    if N == 1:
        return 1
    if N < 1:
        raise ValueError(f"N must be a positive integer. Got {N}.")
    
    # First replace N with an odd number dividing N
    while N%2 == 0:
        N //= 2
    
    # Construct a number with lots of small prime factors
    M = 1
    smoothnessBound = primeList[-1] + 1
    for p in primeList:
        P = p
        while P < smoothnessBound:
            M *= p
            P *= p
    
    a = 2
    i = -1
    while (d:=gcd(pow(a, M, N) - 1, N)) == N:
        M //= primeList[i]
        i -= 1
    
    return d

def factorise(N: int) -> list[int]:
    """
    Compute a factorisation of the given input. The factorisation is not 
    guaranteed to be complete.

    Args:
        N (int): The number to be factored.

    Returns:
        list[int]: The factors.
    """
    if N == 1 or miller_rabin_test(N):
        return [N]
    
    factors = []
    # First get rid of all the smallest factors
    # print("Attempting trial division for small primes.")
    for p in primeList:
        while N % p == 0:
            N //= p
            factors.append(p)
    
    # Now try Pollard's p-1 as many times as gets us somewhere.
    p = pollardP_1(N)
    if p != 1:
        newFactors = factorise(p)
        N //= prod(newFactors)
        factors += newFactors
    
    # Don't bother with Pollard's rho unless we need to.
    if N == 1:
        return sorted(factors)
    if miller_rabin_test(N):
        return sorted(factors + [N])
    
    # Now try Pollard's-rho
    while N != 1:
        p = pollardRho(N)
        if p == 1 or p == N:
            break
        else:
            while N%p == 0:
                N //= p
                factors.append(p)
    
    # Give up on factoring if we haven't figured it out yet.
    if N != 1:
        factors.append(N)
        
    return sorted(factors)
    