"""
Ciphertext-only attacks on generic block ciphers.

These attacks assume the attacker has access only to the ciphertext output of a generic block cipher.

There is very little we can do with just ciphertext here so this module is quite sparse.
"""

from typing import Collection, Union
from cryptolib.utils.byteops import bytes_to_blocks

def evidence_of_ECB(cipher: Union[bytes, Collection[bytes]], 
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
    if not isinstance(cipher, Collection):
        cipher = [cipher]

    blocks = []
    for c in cipher:
        blocks += bytes_to_blocks(c, block_size=block_size)

    return (len(blocks) != len(set(blocks)))
