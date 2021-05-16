"""
Functions for breaking ciphers related to substitution ciphers.
"""

from ..utils.byteops import cyclical_xor, hamming_distance
from ..utils.plain_scoring import score
from collections.abc import Collection

def decrypt_single_byte_xor(ciphertext: bytes) -> bytes:
    """
    Finds the best decryption of the ciphertext assuming a single byte xor cipher.
    """
    best_plaintext = ciphertext
    best_score = score(ciphertext)
    for int_key in range(256):
        key = bytes([int_key])
        plaintext = cyclical_xor(key, ciphertext)
        this_score = score(plaintext)
        if this_score < best_score:
            best_plaintext = plaintext
            best_score = this_score

    return best_plaintext

def decrypt_repeating_key_xor(
    ciphertext: bytes, 
    keylengths: Collection[int], 
    scoring_system: str = 'scrabble'
    ) -> bytes:
    """
    Attempts to decrypt a string of bytes assuming a repeating key xor cipher.

    Tries keys of each length in the keylengths argument. Scores decryptions based on the scoring_system argument.
    """
    raise NotImplementedError()
    # return bytes('')