"""
Functions for breaking two time pads and related problems.
"""

from typing import Optional
from ..utils.byteops import cyclical_xor, transpose
from ..utils.plain_scoring import score

def decrypt_single_byte_xor(
        ciphertext: bytes, 
        scorer: Optional[dict] = None) -> bytes:
    """
    Finds the best decryption of the ciphertext assuming a single byte has been xored all the text
    """
    best_plaintext = ciphertext
    best_score = score(ciphertext, scorer=scorer)
    best_key = 0
    for int_key in range(1, 256):
        key = bytes([int_key])
        plaintext = cyclical_xor(key, ciphertext)
        this_score = score(plaintext, scorer=scorer)
        if this_score < best_score:
            best_plaintext = plaintext
            best_score = this_score
            best_key = int_key

    return best_plaintext, best_key

def decrypt_two_time_pad(
        messages: list[bytes], 
        scorer: Optional[dict] = None) -> list[bytes]:
    messages_t = transpose(messages)
    plaintexts_t = []
    key = b''
    for message in messages_t:
        p, k = decrypt_single_byte_xor(message, scorer)
        plaintexts_t.append(p)
        key += bytes([k])
    plaintexts = transpose(plaintexts_t)
    return plaintexts, key