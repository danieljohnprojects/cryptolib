"""
Attacks on block cipher oracles.
"""

from functools import reduce
from math import gcd
from typing import Tuple

from ..oracles import AdditionalPlaintextOracle, BCOracle
from ..utils.byteops import bytes_to_blocks

def get_block_size(oracle: BCOracle, max_size: int = 20):
    """
    Attempts to determine the block size of the given oracle.
    
    Does this by sending messages of differing lengths and finding when the length of the returned message changes. The max_size argument is thus the maximum length of message sent to the oracle, not the maximum block size it can detect. In some cases it is possible to detect a block size greater than the length of the message sent.
    """
    if max_size < 1:
        raise ValueError(f"max_size must be positive! Got {max_size}.")

    message = b''
    cipher_lens = []
    while len(message) < max_size + 1:
        cipher_lens.append(len(oracle.divine(message)))
        message += b'a'
    cipher_lens = sorted(list(set(cipher_lens)))
    if len(cipher_lens) == 1:
        raise ValueError("Length of return message did not change! Either max_size is too small or the given oracle does not use a block cipher.")
    # In case the oracle adds some stuff after encryption we want the difference of each element with the smallest length.
    block_lens = [l - min(cipher_lens) for l in cipher_lens]

    B = reduce(gcd, block_lens)
    return B

def uses_ECB(oracle: BCOracle, block_size: int = 16) -> bool:
    """
    Determines if a block cipher oracle is in ECB mode.

    We assume that the oracle may add a prefix or suffix to a message before encrypting.
    """
    # We detect ECB by looking for repeated blocks in the cipher. Thus we need 
    # to send two blocks of identical text.
    # The presence of a prefix means that we may not be able to control what is 
    # in the first few blocks.
    # Similarly for a suffix and the last few blocks.
    # Each of these additional strings could be as small as 1 byte so to 
    # guarantee two repeated blocks our message must have length: 
    # (block_size - 1) + 2*block_size + (block_size - 1)
    # = 4*block_size - 2
    message = bytes(b'a' * (4*block_size - 2))
    ciphertext = oracle.divine(message)
    # Chop up the ciphertext and look for repeats.
    N = len(ciphertext) // block_size
    blocks = [ciphertext[i*block_size: (i+1)*block_size] for i in range(N)]
    # If any blocks repeat set(blocks) will have less elements than blocks
    return (len(blocks) != len(set(blocks)))

def get_additional_message_len(
        oracle: AdditionalPlaintextOracle, 
        block_size: int
        ) -> Tuple[int,int]:
    """
    Determines the length of any prefix and suffix added to a message before being encrypted by an block cipher oracle that uses a fixed IV.

    The method for determining the prefix length is easiest explained with an example:

    Suppose we have an oracle that takes a message, prepends 'A' to it, appends 'B' to it, pads the altered message, and finally encrypts it with a block size of 4. So given an empty string the oracle returns the encryption of the string "AB\x02\x02".
    The following messages are sent, processed and received back in pairs:
    a    -> AaB.|     -> ****
    b    -> AbB.|     -> ****
    aa   -> AaaB|.... -> ********
    ab   -> AabB|.... -> ********
    aaa  -> Aaaa|B... -> ********
    aab  -> Aaab|B... -> ********
    aaaa -> Aaaa|aB.. -> yyyy****
    aaab -> Aaaa|bB.. -> yyyy****
    We see that in the first three pairs of messages the ciphers returned by the oracle all differ in the first block. In the final pair the messages the first block of cipher is the same.
    We thus need to send pairs of messages until we see a change in the index of the first block that differs.

    The total length of the additional plaintext is easily determined by keeping track of when the ciphertext length jumps.

    The suffix length is just the difference of the total length and the prefix length.
    """
    
    indexes = []
    lengths = []
    for i in range(block_size):
        # Send two messages that differ in the ith byte.
        zero_enc = oracle.divine(b'\x00' * i + b'\x00')
        one_enc  = oracle.divine(b'\x00' * i + b'\xff')

        # Keep track of lengths of replies.
        lengths.append(len(zero_enc))

        # Determine the first block in which the replies differ.
        zero_blocks = bytes_to_blocks(zero_enc, block_size)
        one_blocks = bytes_to_blocks(one_enc, block_size)
        same_blocks = [x == y for x, y in zip(zero_blocks, one_blocks)]
        try:
            message_block_idx = same_blocks.index(False)
        except ValueError:
            raise ValueError("Oracle does not work as expected! Encrypts different messages to same output.")
        indexes.append(message_block_idx)
    
    # Determine total length of added plaintext.
    total_len = lengths[0] - (lengths.count(lengths[0]) + 1)

    # Determine length of prefix
    remainder = block_size - indexes.count(indexes[0])
    prefix_len = (indexes[0] * block_size) + remainder

    suffix_len = total_len - prefix_len

    return prefix_len, suffix_len

def decode_suffix(
    oracle: AdditionalPlaintextOracle, 
    suffix_len: int,
    block_size: int = 16,
    ) -> bytes:
    """
    Decodes the suffix used in an ECB_suffix_oracle object.
    """

    # The maximum number of blocks needed to fit the suffix
    num_blocks = suffix_len // block_size + 1
    message = b'\x00' * block_size * num_blocks
    suffix = b''
    for _ in range(suffix_len):
        # Pop off the first character
        message = message[1:]
        # First character of 
        target = oracle.divine(message)
        for i in range(256):
            trial = oracle.divine(message + suffix + bytes([i]))
            if trial[:num_blocks*block_size] == target[:num_blocks*block_size]:
                # We have found the next byte of the suffix!
                suffix += bytes([i])
                break
    return suffix
