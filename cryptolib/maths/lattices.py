"""
Functions for lattice reduction algorithms. Throughout we think of a lattice basis as a matrix where the rows (rather than columns) form the basis.
"""
import numpy as np
from numpy.linalg import norm


def lagrange_reduce(B):
    """
    Computes a Lagrange reduced basis matrix that defines the same lattice as the provided matrix.
    """
    nRows, _ = np.shape(B)
    assert nRows == 2
    # Set a to be the smaller of the two vectors.
    a, b = (B[0], B[1]) if norm(B[0]) < norm(B[1]) else (B[1], B[0])
    mu = round((b@a) / (a@a))
    while mu != 0:
        b -= mu * a
        a, b = b, a
        mu = round((b@a) / (a@a))
    return np.array([b, a])


def lower_triangle(B, starting_index=0):
    """
    Computes the L part of the LQ decomposition of a basis matrix using Householder reflections.

    The starting_index argument is used to only recompute those parts that have changed. 
    For example if we have just swapped the second and third row, we don't need to recompute the first.
    """
    EPS = 1e-13
    nRows, nCols = np.shape(B[starting_index:, starting_index:])
    assert nRows <= nCols
    # The identity matrix gives us an easy way to get vectors of the form (1, 0, ..., 0)
    I = np.eye(max(nRows, nCols))
    L = B[starting_index:, starting_index:].astype(np.float64)
    L_view = L[0:, 0:]
    # I = I[starting_index:, starting_index:]
    for _ in range(nRows):
        x = L_view[0]
        u = x - norm(x) * I[0]
        # If u is very small the vector points in almost the right direction anyways.
        if norm(u) > EPS:
            # Householder reflection.
            # We might be wasting some computation here since we might not use the lower rows. We'll just cop the hit here.
            L_view -= 2 * \
                L_view @ u.reshape((-1, 1)) @ u.reshape((1, -1)) / (u @ u)
        L_view = L_view[1:, 1:]
        I = I[1:, 1:]
    return L[:, :nRows]


def size_reduce(B, L):
    """
    Size reduces the basis B using the lower triangular matrix L. Does so in place.
    """
    nRows, nCols = np.shape(L)
    for row in range(1, nRows):
        for col in range(row):
            mu = L[row, col] / L[col, col]
            if np.isinf(mu):
                # If we reach this point
                print("Divide by zero!", L)
                raise RuntimeError(
                    "Something bad happened and I don't fully understand it.")
                continue
            mu = round(mu)
            B[row] -= mu*B[col]
            L[row] -= mu*L[col]
            # This probably looks a bit strange since B[col] is a row of the matrix.
            # In the L matrix the [row, col] entry is the magnitude of B[row] in the direction of (projected version of) B[col]


def lovasz_swap(B, L, delta=0.75):
    """
    Searches the basis matrix B for rows that need to be swapped using the lower triangular matrix L. Does so in place.

    Returns the smallest index of the swapped rows or -1 if no rows were swapped.
    """
    nRows, _ = np.shape(L)
    for i in range(nRows - 1):
        if delta*(L[i, i]**2) > (L[i+1, i]**2 + L[i+1, i+1]**2):
            B[[i, i+1], :] = B[[i+1, i], :]
            L[[i, i+1], :] = L[[i+1, i], :]
            return i
    else:
        return -1


def LLL(B, delta=0.75, in_place=False):
    if not in_place:
        B = B.copy()
    L = lower_triangle(B)
    i = 0
    while i >= 0:
        L[i:, i:] = lower_triangle(B, starting_index=i)
        size_reduce(B, L)
        i = lovasz_swap(B, L, delta=delta)
    if not in_place:
        return B


def close_vector_problem(basis, target):
    raise NotImplementedError
    nRows, nCols = np.shape(basis)
    Gamma = max(100.0, np.max(np.abs(basis)) * nCols) ** 3.0
    B = np.block([
        [basis, np.zeros((nRows, 1))],
        [target, Gamma]
    ])
    # B = np.zeros((nRows+1, nCols + 1))
    # B[:-1, :-1] = basis
    # B[-1, :-1] = target
    # B[-1, -1] = np.max(np.abs(basis)) * nCols * 100
    LLL(B)
    assert B[-1, -1] == Gamma
    error = B[-1, :-1]
    close_vector = target - error
    return close_vector
