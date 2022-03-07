"""
Functions for breaking ciphers related to substitution ciphers.
"""

from typing import Optional
from ..cracks.two_time_pad import decrypt_two_time_pad
from ..utils.byteops import block_xor, hamming_distance
from ..utils.plain_scoring import Scorer
from collections.abc import Collection


def decrypt_repeating_key_xor(
        ciphertext: bytes,
        block_sizes: Optional[Collection[int]]=None,
        scorer: Optional[Scorer]=None
        ) -> bytes:
    """
    Attempts to decrypt a string of bytes assuming a repeating key xor cipher.

    If the block_sizes argument is provided only those block sizes will be used, otherwise will try every valid blocks size.
    """    

    if not block_sizes:
        block_sizes = range( 1, min(len(ciphertext)//2 + 1, 13) )

    if min(block_sizes) < 1:
        raise ValueError("block_sizes can only contain positive integers.")
    if max(block_sizes) > len(ciphertext)//2:
        raise ValueError(f"Maximum block size is {len(ciphertext)//2}. Got {max(block_sizes)}.")


    # First we determine the most probable block_size
    block_size = 0

    best_block_score = 8 # the maximum hamming distance between two bytes.
    for L in block_sizes:
        num_blocks = len(ciphertext) // (2*L)
        # Get N chunks of length 2*L
        c = ciphertext[:num_blocks*2*L]
        blocks = [c[2*L*n:2*L*(n+1)] for n in range(num_blocks)]
        # Compute the average normalised edit distance (chunk score)
        block_scorer = lambda chunk: hamming_distance(chunk[:L], chunk[L:])
        ave_block_score = sum(map(block_scorer, blocks)) / (num_blocks*L)
        # print(ave_block_score)
        if ave_block_score < best_block_score:
            best_block_score = ave_block_score
            block_size = L

    # Now block_size is hopefully the actual length of the key
    # We treat the blocks of ciphertext as a two time pad problem
    # Transpose the ciphertext on block_size boundaries
    cipher_blocks = [
        ciphertext[n*block_size: (n+1)*block_size] 
        for n in range(len(ciphertext) // block_size)
    ]
    remainder = ciphertext[-(len(ciphertext)%block_size):] if len(ciphertext)%block_size else b''
    plaintexts, key = decrypt_two_time_pad(cipher_blocks, scorer)
    plaintext = b''.join(plaintexts)
    plaintext += block_xor(remainder, key[:len(remainder)])

    return plaintext, key
