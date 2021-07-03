"""
Attacks on block cipher oracles.

The attacks in this module assume the following model for oracles:
1. Oracles have a single public divine method that takes in a string of bytes and returns a string of bytes.
2. The oracle has a private white list of "allowed" bytes. The behaviour of the oracle upon receiving a message including a disallowed byte is undefined.
3. Given a string consisting of allowed bytes, the oracle will prepend and append the message with fixed private strings.
4. The oracle will encrypt the altered message using a block cipher in ECB mode with a fixed private key, or in CBC mode with key and IV both fixed and private.
5. The oracle then returns the encrypted byte string to the user.
"""

from functools import reduce
from math import gcd
from textwrap import dedent
from typing import Optional, Tuple

from ..oracles import AdditionalPlaintextOracle, PaddingOracle
from ..pipes import Pipe
from ..utils.byteops import block_xor, bytes_to_blocks


def get_block_size(
        oracle: Pipe,
        max_size: int = 20,
        allowable_bytes: Optional[bytes] = b'') -> int:
    """
    Attempts to determine the block size of the given oracle.

    Does this by sending messages of differing lengths and finding when the length of the returned message changes. The max_size argument is thus the maximum length of message sent to the oracle, not the maximum block size it can detect. In some cases it is possible to detect a block size greater than the length of the message sent.

    If the oracle is known to have special treatment of certain bytes (for example quotes out some special characters) they can be avoided by specifying the allowable_bytes argument. If no argument is provided there are no guarantees on what bytes are sent.
    """
    if max_size < 1:
        raise ValueError(f"max_size must be positive! Got {max_size}.")

    if allowable_bytes:
        c = bytes([allowable_bytes[0]])
    else:
        c = b'\x00'

    message = b''
    cipher_lens = []
    while len(message) < max_size + 1:
        cipher_lens.append(len(oracle(message)))
        message += c
    cipher_lens = sorted(list(set(cipher_lens)))
    if len(cipher_lens) == 1:
        raise ValueError(
            "Length of return message did not change! Either max_size is too small or the given oracle does not use a block cipher.")
    # In case the oracle adds some stuff after encryption we want the difference of each element with the smallest length.
    block_lens = [l - min(cipher_lens) for l in cipher_lens]

    B = reduce(gcd, block_lens)
    return B


def uses_ECB(
        oracle: Pipe,
        block_size: int = 16,
        allowable_bytes: Optional[bytes] = b'') -> bool:
    """
    Determines if a block cipher oracle is in ECB mode.

    We assume that the oracle may add a prefix or suffix to a message before encrypting.

    If the oracle is known to have special treatment of certain bytes (for example quotes out some special characters) they can be avoided by specifying the allowable_bytes argument. If no argument is provided there are no guarantees on what bytes are sent.
    """
    if allowable_bytes:
        c = bytes([allowable_bytes[0]])
    else:
        c = b'\x00'

    # We detect ECB by looking for repeated blocks in the cipher. Thus we need
    # to send two blocks of identical text.
    # The presence of a prefix means that we may not be able to control what is
    # in the first few blocks.
    # Similarly for a suffix and the last few blocks.
    # Each of these additional strings could be as small as 1 byte so to
    # guarantee two repeated blocks our message must have length:
    # (block_size - 1) + 2*block_size + (block_size - 1)
    # = 4*block_size - 2
    message = bytes(c * (4*block_size - 2))
    ciphertext = oracle(message)
    # Chop up the ciphertext and look for repeats.
    blocks = bytes_to_blocks(ciphertext, block_size)
    # If any blocks repeat set(blocks) will have less elements than blocks
    return (len(blocks) != len(set(blocks)))


def get_additional_message_len(
        oracle: Pipe,
        block_size: int = 16,
        allowable_bytes: Optional[bytes] = b'') -> Tuple[int, int]:
    """
    Determines the length of any prefix and suffix added to a message before being encrypted by an block cipher oracle that uses ECB mode or CBC and a fixed IV.

    Arguments:
        oracle
            An oracle object of the form in the module description.
        block_size
            The block size used by the oracle
        allowable_bytes
            A byte string consisting of bytes that are safe to send. Ones that won't be quoted out for example.

    The method for determining the prefix length is most easily explained with an example:

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
    if allowable_bytes:
        # Need to make sure we don't use the same byte for c and d.
        s = set(allowable_bytes)
        if len(s) < 2:
            raise ValueError(
                "allowable_bytes must have at least two distinct bytes")
        c = bytes([s.pop()])
        d = bytes([s.pop()])
    else:
        c = b'\x00'
        d = b'\x01'

    indexes = []
    lengths = []
    for i in range(block_size):
        # Send two messages that differ in the ith byte.
        zero_enc = oracle(c * i + c)
        one_enc = oracle(c * i + d)

        # Keep track of lengths of replies.
        lengths.append(len(zero_enc))

        # Determine the first block in which the replies differ.
        zero_blocks = bytes_to_blocks(zero_enc, block_size)
        one_blocks = bytes_to_blocks(one_enc, block_size)
        same_blocks = [x == y for x, y in zip(zero_blocks, one_blocks)]
        try:
            message_block_idx = same_blocks.index(False)
        except ValueError:
            raise ValueError(
                "SequentialOracle does not work as expected! Encrypts different messages to same output.")
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
        prefix_len: int = 0,
        block_size: int = 16,
        allowable_bytes: Optional[bytes] = b'') -> bytes:
    """
    Decodes the suffix used in an ECB_suffix_oracle object.

    If suffix contains any of the characters not in the allowable_bytes argument it will only decode the bytes up to the first instance of such a byte and then raise an exception.
    """
    # Number of blocks taken up by the prefix:
    num_prefix_blocks = prefix_len // block_size + 1

    # Make sure bytes in allowable bytes are unique
    allowable_bytes = bytes(set(allowable_bytes))
    if allowable_bytes:
        c = bytes([allowable_bytes[0]])
    else:
        c = b'\x00'
        allowable_bytes = bytes(range(256))

    # To make life simple we fill out the prefix blocks if needed
    message = c * (num_prefix_blocks * block_size - prefix_len)
    # The maximum number of blocks needed to fit the suffix
    num_suffix_blocks = suffix_len // block_size + 1
    message += c * block_size * num_suffix_blocks
    suffix = b''

    for _ in range(suffix_len):
        # Pop off the first character
        message = message[1:]
        # First character of
        encrypted_blocks = bytes_to_blocks(oracle(message), block_size)
        target_block = encrypted_blocks[num_prefix_blocks +
                                        num_suffix_blocks - 1]
        for i in allowable_bytes:
            trial_blocks = bytes_to_blocks(oracle(
                message + suffix + bytes([i])), block_size)
            trial_block = trial_blocks[num_prefix_blocks +
                                       num_suffix_blocks - 1]
            if trial_block == target_block:
                # We have found the next byte of the suffix!
                suffix += bytes([i])
                break
        else:
            # We could not find the next byte of the suffix
            avoid_bytes = bytes(set(range(256)) - set(allowable_bytes))
            raise RuntimeError(dedent(f"""Could not decode the next byte of the suffix. This should only happen if the next byte was not included in the allowable_bytes argument.
            Suffix up to this point was "{suffix}". The next byte is one of "{avoid_bytes}"."""))
    return suffix


def decrypt_with_padding_oracle(
        message: bytes,
        oracle: PaddingOracle,
        mode: str,
        block_size: int = 16) -> bytes:
    """
    Decrypts a message using an oracle that reveals only whether a given message is correctly padded.

    For example in CBC mode. Suppose we have some ciphertext that would normally decrypt like so:
    |****|****|****|  ------> |0123|4567|8333|
    Note the 3s in the final block of plaintext are padding.

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
    """
    if mode.lower() == 'cbc':
        pass
    else:
        raise NotImplementedError(
            "Padding attacks are currently only implemented for CBC mode.")

    # We need a convenient way of setting the iv in the oracle

    # We need to use this over and over so make it read only
    cipher_blocks = tuple(bytes_to_blocks(message, block_size))
    if len(cipher_blocks) < 2:
        raise ValueError(
            f"Ciphertext must consist of at least two blocks, the first being the IV. Got {len(cipher_blocks)}.")

    # We'll overwrite this copy a bunch
    blocks = list(cipher_blocks)
    decrypted_message = b''
    decrypted_block = b''

    ###########################
    #### Determine padding ####
    ###########################
    # First we need to determine the padding by decrypting the very last byte
    # of the message.
    # The last byte must be in the range [0x01, block_size].
    # We test for a particular byte by trying to turn it into a 0x01.
    # We'll check each of the numbers from 2 to blocksize first.

    for c in range(2, block_size + 1):
        mask = bytes([0]*(block_size-1) + [c ^ 1])
        blocks[-2] = block_xor(cipher_blocks[-2], mask)
        if oracle(b''.join(blocks)) == b'good':
            break
    # We can't really test for the 0x01 byte so if it's not one of the others
    # we assume it's a 1. This is safe as long as we know the message is padded
    # according to pkcs7
    else:
        c = 1
    decrypted_block = bytes(c*[c])

    ############################
    #### Decrypt end blocks ####
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
            for c in range(256):
                mask = zero_mask + bytes([c]) + plain_mask
                blocks[-2] = block_xor(cipher_block, mask)
                if oracle(b''.join(blocks)) == b'good':
                    # c ^ plaintext == pad_value
                    # so plaintext == c ^ pad_value
                    decrypted_block = bytes([c ^ pad_value]) + decrypted_block
                    break
            else:
                raise RuntimeError(dedent("""Padding oracle attack failed!
                    Something has gone terribly wrong!! 
                    This could be because the oracle you provided is not in the correct mode or perhaps because they don't use pkcs#7 padding. Or maybe because of some error in my code."""))
        decrypted_message = decrypted_block + decrypted_message
        decrypted_block = b''
        blocks.pop()
        blocks[-1] = cipher_block

    return decrypted_message
