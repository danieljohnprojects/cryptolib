"""
Functions for generating and testing primes.
"""
import random
from typing import Optional

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