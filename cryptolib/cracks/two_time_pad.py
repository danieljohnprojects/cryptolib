"""
Functions for breaking two time pads and related problems.
"""

from typing import Optional, Tuple
from ..utils.byteops import cyclical_xor, block_xor

from ..utils.plain_scoring import Scorer, ScrabbleScorer

def decrypt_single_byte_xor(
        ciphertext: bytes, 
        scorer: Optional[Scorer] = None) -> bytes:
    """
    Finds the best decryption of the ciphertext assuming a single byte has been xored all the text
    """
    if not scorer:
        scorer = ScrabbleScorer()

    best_plaintext = ciphertext
    best_score = scorer.score(ciphertext)
    best_key = bytes(1)
    for int_key in range(1, 256):
        key = bytes([int_key])
        plaintext = cyclical_xor(key, ciphertext)
        this_score = scorer.score(plaintext)
        if this_score < best_score:
            best_plaintext = plaintext
            best_score = this_score
            best_key = key

    return best_plaintext, best_key

def decrypt_two_time_pad(
        messages: list[bytes], 
        scorer: Optional[Scorer] = None
        ) -> Tuple[list[bytes], bytes]:
    """
    Takes in a list of messages that have all been xored against the same key stream and determines the most likely decryptions according to the plaintext scorer provided.

    Note that the decryption will only work if you have a reasonable idea of what sort of text will show up and score appropriately. For example using the default scrabble scorer to try and decrypt Japanese will not produce good results.

    The decryptions are more likely to be good given more samples. If some messages are longer than others the ends of the long messages will not decrypt as well as the beginnings.
    """

    if not scorer:
        scorer = ScrabbleScorer()

    remaining_messages = messages.copy()
    N = max([len(m) for m in remaining_messages])
    keystream = b''
    for _ in range(N):
        # Determine the byte of the key used for each character.
        ith_chars = b''
        for i in range(len(remaining_messages)):
            message = remaining_messages[i]
            ith_chars += message[:1]
            remaining_messages[i] = message[1:]
        _, k = decrypt_single_byte_xor(ith_chars, scorer)
        keystream += k

    # Now xor the keystream onto each message
    plaintexts = []
    for message in messages:
        plaintexts.append(block_xor(message, keystream[:len(message)]))

    return plaintexts, keystream