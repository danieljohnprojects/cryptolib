"""
Functions for breaking ciphers related to substitution ciphers.
"""

from ..cracks.two_time_pad import decrypt_two_time_pad
from ..utils.byteops import block_xor, hamming_distance
from collections.abc import Collection


def decrypt_repeating_key_xor(
        ciphertext: bytes,
        block_sizes: Collection[int],
        num_blocks: int = 8) -> bytes:
    """
    Attempts to decrypt a string of bytes assuming a repeating key xor cipher.

    Tries for keys of each length in the block_sizes argument. 

    The num_blocks argument determines how many blocks are used to estimate the block_size. Higher is usually better if there is sufficient data.

    Raises an error if the ciphertext is not at least twice as long as the maximum of block_sizes. 
    """

    if len(ciphertext) < 2*max(block_sizes)*num_blocks:
        raise ValueError(
            f"Not enough ciphertext to get {num_blocks} chunks of length {max(block_sizes)}. Try with more ciphertext, a smaller number of chunks or with smaller key lengths.")
    
    # First we determine the most probable block_size
    block_size = 0

    best_block_score = 8 # the maximum hamming distance between two bytes.
    for L in block_sizes:
        # Get N chunks of length 2*L
        blocks = [ciphertext[2*L*n:2*L*(n+1)] for n in range(num_blocks)]
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
    remainder = ciphertext[-(len(ciphertext)%block_size):]
    plaintexts, key = decrypt_two_time_pad(cipher_blocks)
    plaintext = b''.join(plaintexts)
    plaintext += block_xor(remainder, key[:len(remainder)])

    return plaintext, key
