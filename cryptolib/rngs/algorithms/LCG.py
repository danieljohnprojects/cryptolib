from .RNG import RNGEngine

class LCG(RNGEngine):
    """
    Generates randome numbers according to the recurrence:
    X <- (aX + c) % m

    One must choose the numbers a, c, and m carefully to ensure good randomness properties. 
    
    The Hull Dobell theorem states that an LCG will have full period if and only if:
        1. m and c are coprime.
        2. a-1 is divisible by all prime factors of m.
        3. a-1 is divisible by 4 if m is divisible by 4. 
    
    According to wikipedia, the spectral test is an important test for randomness here.
    """

    def __init__(self, seed: int):
        """
        Initiate the LCG with some fairly arbitrary values
        """
        self.a = 134775813
        self.c = 1
        self.m = 2**32
        self.X = seed

    def __init__(
            self,
            seed: int,
            a: int,
            c: int,
            m: int
        ):
        self.a = a
        self.c = c
        self.m = m
        self.X = seed

    def rand(self) -> int:
        self.X = (self.a * self.X + self.c) % self.m
        return self.X