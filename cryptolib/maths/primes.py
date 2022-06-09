"""
Functions for generating and testing primes.
"""
import random
from typing import Optional

def fermat_test(p: int, samples: int = 10, seed: Optional[int] = None) -> bool:
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
    if p < 100:
        A = [pow(a, p-1, p) == 1 for a in range(1, p)]
        return all(A)
    rng = random.Random(seed)
    A = rng.sample(range(2, p), samples)
    A = [pow(a, p-1, p) == 1 for a in A]
    return all(A)