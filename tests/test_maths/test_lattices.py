import numpy as np
import pytest
import random
from cryptolib.maths.lattices import lagrange_reduce, lower_triangle
from cryptolib.maths.math import xgcd


def test_lagrange_reduce():
    rng = random.Random(12345)

    def sample_SL2():
        """
        Randomly sample a 2x2 matrix with determinant 1.
        """
        a = rng.randint(1, 100)
        b = rng.randint(1, 100)
        g, d, c = xgcd(a, b)
        while g != 1:
            b = rng.randint(1, 100)
            g, d, c = xgcd(a, b)
        return np.array([[a, -b], [c, d]])

    nTests = 50
    for _ in range(nTests):
        B = sample_SL2()
        rB = lagrange_reduce(B)
        assert((rB == np.array([[1, 0], [0, 1]])).all()
               or (rB == np.array([[-1, 0], [0, 1]])).all()
               or (rB == np.array([[1, 0], [0, -1]])).all()
               or (rB == np.array([[-1, 0], [0, -1]])).all()
               or (rB == np.array([[0, 1], [1, 0]])).all()
               or (rB == np.array([[0, -1], [1, 0]])).all()
               or (rB == np.array([[0, 1], [-1, 0]])).all()
               or (rB == np.array([[0, -1], [-1, 0]])).all())


def test_lower_triangle():
    rng = random.Random(12345)

    def gen_matrix(rows, cols):
        return np.array([[rng.randrange(-100, 101)
                          for _ in range(cols)] for _ in range(rows)])

    nTests = 25
    for n in range(nTests):
        B = gen_matrix(n+1, n+1)
        L = lower_triangle(B)
        assert(np.allclose(L, np.tril(L)))

    for n in range(nTests):
        B = gen_matrix(n+1, n+2)
        L = lower_triangle(B)
        assert(np.allclose(L, np.tril(L)))
