"""
Chosen ciphertext attacks on generic block ciphers.

These attacks assume access to an oracle that, when provided with a cipher text string of bytes, returns the decryption of that string, or returns some information about the decryption of that string.

These attacks hope to gain some information about the underlying block cipher, mode of operation, key, or plaintext.

By default oracles are only assumed to be callable objects that take in a single bytes-like argument and return a single bytes-like object. Generally if the oracle requires an IV this is taken to be the first block of ciphertext. Any further assumptions are detailed in the function description.
"""

from textwrap import dedent
from typing import Callable

from cryptolib.utils.byteops import block_xor, bytes_to_blocks


def decrypt_padding_oracle_cbc(
    oracle: Callable,
    ciphertext: bytes,
    block_size: int = 16) -> bytes:
    """
    Decrypts a message using an oracle that reveals only whether a given message is correctly padded.

    The oracle is assumed to raise a ValueError when padding is incorrect, otherwise no assumptions are made about the output, in particular we do not assume that the oracle decrypts the given ciphertext. We assume that the oracle is in CBC mode under the hood.

    The attack works as follows. Suppose we have some ciphertext that would normally decrypt like so:
    |****|****|****|  ------> |0123|4567|8333|
    Note the 3s in the final block of plaintext should be interpreted as padding.

    We xor the final byte of the penultimate block of ciphertext with 0x01. This scrambles the decryption of this block and xors the final byte of the final block of plaintext with 0x01.
      |****|****|****|  
    + |0000|0001|0000|  -----> |0123|####|8332|
    We then query the oracle with the altered ciphertext. This does not pass the padding check. We keep trying until we find a byte that does. Eg:
      |****|****|****|  
    + |0000|0002|0000|  -----> |0123|####|8331|
    This plaintext passes the padding check. But now we know that the original plaintext byte xored with 2 gives 1 so we know the original plaintext byte was 3.
    We continue with the second last byte, looking for the one that gives valid padding:
      |****|****|****|  
    + |0000|0011|0000|  -----> |0123|####|8322|
    Since we know the final byte of plain text we choose the final byte of the penultimate block so that we get valid padding when we guess the next byte.

    The first block of ciphertext is the IV so we don't need to decrypt that one.

    Args:
        oracle: The padding oracle as described above.
        ciphertext: The ciphertext that we want to decrypt.
        block_size: The block size of the block cipher used by the provided oracle.
    Returns:
        The decryption of the ciphertext.
    Raises:
        ValueError: If the provided ciphertext has the wrong length.
        RuntimeError: If the ciphertext could not be decrypted.
    """
    if len(ciphertext) % block_size != 0:
        raise ValueError(f"Length of ciphertext must be a multiple of the provided block size, got {len(ciphertext)}")
    if len(ciphertext) < 2*block_size:
        raise ValueError(f"Ciphertext must contain at least two blocks in order to decrypt! Length of provided ciphertext was {len(ciphertext)}.")

    # We need to use this over and over so make it read only
    cipher_blocks = tuple(bytes_to_blocks(ciphertext, block_size))
    
    # We'll overwrite this copy a bunch
    blocks = list(cipher_blocks)
    decrypted_message = b''
    decrypted_block = b''

    ###########################
    #### Determine padding ####
    ###########################
    # First we need to determine the padding by decrypting the very last byte
    # of the ciphertext.
    # The last byte must be in the range [0x01, block_size].
    # We test for a particular byte by trying to turn it into a 0x01.
    # We'll check each of the numbers from 2 to blocksize first.

    for pad in range(2, block_size + 1):
        mask = bytes([0]*(block_size-1) + [pad ^ 1])
        blocks[-2] = block_xor(cipher_blocks[-2], mask)
        try:
            oracle(b''.join(blocks))
            break
        except:
            continue
    # We can't really test for the 0x01 byte so if it's not one of the others
    # we assume it's a 1. This is safe as long as we know the ciphertext is padded
    # according to pkcs7
    else:
        pad = 1
    decrypted_block = bytes(pad*[pad])

    # Plaintext plus padding should have length equal to the ciphertext minus the IV block
    plaintext_length = len(ciphertext) - block_size

    ############################
    #### Decrypt ciphertext ####
    ############################
    # Now we determine all the bytes in the blocks starting at the end and
    # working backwards.
    for cipher_block in cipher_blocks[-2::-1]:
        for i in range(block_size - len(decrypted_block) - 1, -1, -1):
            # The value that we want to get as padding
            pad_value = block_size - i
            # The following will xor onto the plaintext, giving the desired padding.
            plain_mask = block_xor(
                bytes([pad_value]) * len(decrypted_block),
                decrypted_block
            )
            # Don't want to touch the bytes at the beginning yet.
            zero_mask = bytes(i)
            for pad in range(256):
                mask = zero_mask + bytes([pad]) + plain_mask
                blocks[-2] = block_xor(cipher_block, mask)
                try:
                    oracle(b''.join(blocks))
                    decrypted_block = bytes([pad ^ pad_value]) + decrypted_block
                    break
                except:
                    continue
            else:
                raise RuntimeError(dedent("""Padding oracle attack failed!
                    Something has gone terribly wrong!! 
                    This could be because the oracle you provided is not in the correct mode or perhaps because they don't use pkcs#7 padding. Or maybe because of some error in my code."""))
        decrypted_message = decrypted_block + decrypted_message
        decrypted_block = b''
        blocks.pop()
        blocks[-1] = cipher_block

    assert len(decrypted_message) == plaintext_length, f"decrypted length: {len(decrypted_message)}, expected length: {plaintext_length}"

    return decrypted_message
