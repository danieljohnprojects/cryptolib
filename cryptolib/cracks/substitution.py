"""
Functions for breaking ciphers related to substitution ciphers.
"""

from ..utils.byteops import cyclical_xor, hamming_distance
from ..utils.plain_scoring import score
from collections.abc import Collection
from math import floor

def decrypt_single_byte_xor(ciphertext: bytes) -> bytes:
    """
    Finds the best decryption of the ciphertext assuming a single byte xor cipher.
    """
    best_plaintext = ciphertext
    best_score = score(ciphertext)
    best_key = 0
    for int_key in range(256):
        key = bytes([int_key])
        plaintext = cyclical_xor(key, ciphertext)
        this_score = score(plaintext)
        if this_score < best_score:
            best_plaintext = plaintext
            best_score = this_score
            best_key = int_key

    return best_plaintext, best_key

def decrypt_repeating_key_xor(
    ciphertext: bytes, 
    keylengths: Collection[int],
    num_chunks: int = 8
    ) -> bytes:
    """
    Attempts to decrypt a string of bytes assuming a repeating key xor cipher.

    Tries for keys of each length in the keylengths argument. 

    The num_chunks argument determines how many chunks are used to estimate the keylength. Higher is usually better if there is sufficient data.

    Raises an error if the ciphertext is not at least twice as long as the maximum of keylengths. 
    """

    if len(ciphertext) < 2*max(keylengths)*num_chunks:
        raise ValueError(f"Not enough ciphertext to get {num_chunks} chunks of length {max(keylengths)}. Try with more ciphertext, a smaller number of chunks or with smaller key lengths.")
    keylength = 0
    best_chunk_score = 8 # This is the maximum possible hamming distance between two bytes.
    for L in keylengths:
        # Get N chunks of length 2*L
        chunks = [ciphertext[2*L*n:2*L*(n+1)] for n in range(num_chunks)]
        # Compute the average normalised edit distance (chunk score)
        chunk_scorer = lambda chunk: hamming_distance(chunk[:L], chunk[L:])
        ave_chunk_score = sum(map(chunk_scorer, chunks)) / (num_chunks*L)
        # print(ave_chunk_score)
        if ave_chunk_score < best_chunk_score:
            best_chunk_score = ave_chunk_score
            keylength = L

    # Now keylength is hopefully the actual length of the key
    # Transpose the ciphertext on keylength boundaries
    cipher_T = [bytes(ciphertext[i::keylength]) for i in range(keylength)]
    get_key = lambda b: decrypt_single_byte_xor(b)[1]
    key = bytes(map(get_key, cipher_T))

    return cyclical_xor(key, ciphertext), key
    # raise NotImplementedError()