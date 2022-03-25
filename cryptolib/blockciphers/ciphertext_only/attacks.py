"""
Ciphertext-only attacks on generic block ciphers.

These attacks assume the attacker has access only to the ciphertext output of a generic block cipher.

There is very little we can do with just ciphertext here so this module is quite sparse.
"""

from math import gcd
from typing import Collection, Union
from cryptolib.utils.byteops import bytes_to_blocks


def get_max_block_size(ciphertexts: Collection[bytes]) -> int:
    """
    Given a collection of ciphertexts, each assumed to have been created from the same block cipher, determines the maximum possible block size.

    This simply takes the gcd of the lengths of the messages.

    Args:
        ciphertexts: A collection of ciphertexts coming from the same block cipher.
    Returns:
        The maximum possible block size of the algorithm used to create the ciphertexts.
    """
    return gcd(*[len(c) for c in ciphertexts])


def evidence_of_ECB(ciphertext: Union[bytes, Collection[bytes]], 
                    block_size: int = 16) -> bool:
    """
    Searches for evidence that the provided ciphertext(s) was(/were) encrypted under Electronic CodeBook (ECB) mode using the same key.

    Does this by looking for any repeated blocks among the provided ciphertexts. It is assumed that the block size is sufficiently large that any repeated blocks are very unlikely in any mode other than ECB.

    Args:
        cipher: A string of bytes or collection of strings of bytes to test.
        block_size: The suspected block size of the underlying block cipher.
    Returns:
        True if evidence is found, False otherwise.
    """
    if not isinstance(ciphertext, Collection):
        ciphertext = [ciphertext]

    blocks = []
    for c in ciphertext:
        blocks += bytes_to_blocks(c, block_size=block_size)

    return (len(blocks) != len(set(blocks)))

