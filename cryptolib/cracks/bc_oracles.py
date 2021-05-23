"""
Attacks on block cipher oracles.
"""

from functools import reduce
from math import gcd

from ..oracles import BCOracle, ECB_suffix_oracle

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

def get_additional_message_len(oracle: BCOracle) -> int:
    """
    Determines the length of the plaintext being added to a message before encryption is performed in a block cipher oracle.

    Does this by comparing the length of an encryption of the empty string with the encryption of strings of varying length. 
    """
    message = b''
    init_len = len(oracle.divine(message))
    while (len(oracle.divine(message)) == init_len):
        message += b'a'
    return init_len - len(message)

def decode_suffix(oracle: ECB_suffix_oracle, block_size: int = 16) -> bytes:
    """
    Decodes the suffix used in an ECB_suffix_oracle object.
    """
    suffix_len = get_additional_message_len(oracle)
    # The number of blocks needed to fit in the message
    num_blocks = suffix_len // block_size + 1
    message = b'\x00' * block_size * num_blocks
    suffix = b''
    for _ in range(suffix_len):
        # Pop off the first character
        message = message[1:]
        target = oracle.divine(message)
        for i in range(256):
            trial = oracle.divine(message + suffix + bytes([i]))
            if trial[:num_blocks*block_size] == target[:num_blocks*block_size]:
                # We have found the next byte of the suffix!
                suffix += bytes([i])
                break
                
    return suffix
