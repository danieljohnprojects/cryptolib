"""
Chosen plaintext attacks on generic block ciphers.

These attacks assume access to an oracle that, when provided with a plain text string of bytes, returns the encryption of that string, or returns some information about the encryption of that string.

These attacks hope to gain some information about the underlying block cipher, mode of operation, or key.

By default oracles are only assumed to be callable objects that take in a single byte-like argument and return a single byte-like object. Any further assumptions are detailed in the function description.
"""

from math import gcd
from textwrap import dedent
from typing import Callable, Optional, Tuple

from cryptolib.blockciphers.ciphertext_only.attacks import evidence_of_ECB
from cryptolib.utils.byteops import block_xor, bytes_to_blocks
from cryptolib.utils.padding import pkcs7

def get_block_size(
        oracle: Callable,
        max_size: int = 32,
        allowable_bytes: Optional[bytes] = b'') -> int:
    """
    Attempts to determine the block size of the given oracle.

    Does this by sending messages of differing lengths and finding when the length of the returned message changes. The max_size argument is thus the maximum length of message sent to the oracle, not the maximum block size it can detect. In some cases it is possible to detect a block size greater than the length of the message sent.

    If the oracle is known to have special treatment of certain bytes (for example quotes out some special characters) they can be avoided by specifying the allowable_bytes argument. If no argument is provided there are no guarantees on what bytes are sent.

    Args:
        oracle: A function that takes in a sequence of bytes, encrypts it and returns the corresponding ciphertext.
        max_size: The maximum message length given to the oracle.
        allowable_bytes: A string of bytes that are allowed to be given to the oracle. If this is empty it is assumed that any byte is allowed.
    Returns:
        The block size used in the underlying block cipher of the oracle.
    Raises:
        ValueError: if max_size is non-positive or if max_size was too small to observe a change in the length of the encrypted message.
    """
    if max_size < 1:
        raise ValueError(f"max_size must be positive! Got {max_size}.")

    if allowable_bytes:
        c = bytes([allowable_bytes[0]])
    else:
        c = b'a'

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

    return gcd(*block_lens)


def get_additional_message_len(
        oracle: Callable,
        block_size: int = 16,
        allowable_bytes: Optional[bytes] = b'') -> Tuple[int, int]:
    """
    Determines the length of any prefix and suffix added to a message before being encrypted by a block cipher.

    We assume that the IV is not present in the ciphertext returned from the oracle and that if an IV is used by the oracle, it remains fixed.

    The method for determining the prefix length is most easily explained with an example:

    Suppose we have an encryption oracle that takes a message, prepends 'A' to it, appends 'B' to it, pads the altered message, and finally encrypts it with a block size of 4. So given an empty string the oracle returns the encryption of the string "AB\x02\x02".
    The following pairs of messages are sent, processed and received back:

    a    -> AaB.|     -> ****
    b    -> AbB.|     -> ****
    
    aa   -> AaaB|.... -> ********
    ab   -> AabB|.... -> ********
    
    aaa  -> Aaaa|B... -> ********
    aab  -> Aaab|B... -> ********
    
    aaaa -> Aaaa|aB.. -> yyyy****
    aaab -> Aaaa|bB.. -> yyyy****
    
    We see that in the first three pairs of messages the ciphers returned by the oracle all differ in the first block. In the final pair the messages the first block of ciphertext is the same. We thus need to send pairs of messages until we see a change in the index of the first block that differs.

    The total length of the additional plaintext is easily determined by keeping track of when the ciphertext length jumps.

    The suffix length is just the difference of the total length and the prefix length.

    Args:
        oracle: An oracle that takes in plaintext and possibly adds a prefix and suffix before encrypting.
        block_size: The block size used by the oracle.
        allowable_bytes: A byte string consisting of bytes that are safe to send. Ones that won't be quoted out for example. By default it is assumed that all bytes are safe.
    Returns:
        The length of the prefix and suffix added to the plaintext prior to encryption.
    Raises:
        ValueError: If the allowable_bytes argument consists of less than two distinct characters.
        RuntimeError: If the oracle encrypts the two different messages to the same cipher or if the oracle encrypts the same message to different ciphertexts.
    """
    if allowable_bytes:
        # Need to make sure we don't use the same byte for c and d.
        s = set(allowable_bytes)
        if len(s) < 2:
            raise ValueError("allowable_bytes must have at least two distinct bytes")
        a = bytes([s.pop()])
        b = bytes([s.pop()])
    else:
        a = b'a'
        b = b'b'

    # Send the same message twice to check that they encrypt the same.
    if oracle(a) != oracle(a):
        raise RuntimeError("Provided oracle appears to use randomised encryption. This function only supports deterministic encryption.")

    indices = []
    lengths = []
    for i in range(block_size):
        # Send two messages that differ in the ith byte.
        a_enc = oracle(a * i + a)
        b_enc = oracle(a * i + b)

        # Keep track of lengths of replies.
        lengths.append(len(a_enc))

        # Determine the first block in which the replies differ.
        a_blocks = bytes_to_blocks(a_enc, block_size)
        b_blocks = bytes_to_blocks(b_enc, block_size)
        same_blocks = [x == y for x, y in zip(a_blocks, b_blocks)]
        try:
            message_block_idx = same_blocks.index(False)
        except ValueError:
            raise RuntimeError(
                "SequentialOracle does not work as expected! Encrypts different messages to same output.")
        indices.append(message_block_idx)

    # Determine total length of added plaintext.
    total_len = lengths[0] - (lengths.count(lengths[0]) + 1)

    # Determine length of prefix
    remainder = block_size - indices.count(indices[0])
    prefix_len = (indices[0] * block_size) + remainder

    suffix_len = total_len - prefix_len

    return prefix_len, suffix_len


def diagnose_mode(
        oracle: Callable,
        block_size: int,
        prefix_length: int = 0,
        allowable_bytes: Optional[bytes] = b'') -> str:
    """
    Determines the mode of operation for the given block cipher oracle. This is only possible if the oracle uses a fixed IV or is in ECB mode.

    It is assumed that the oracle will pad the given message and possibly prepend the IV (if it uses one).

    Args:
        oracle: The block cipher oracle.
        block_size: The block size of the oracle.
        allowable_bytes:  A string of bytes that are allowed to be given to the oracle. If this is empty it is assumed that any byte is allowed.
    Returns:
        One of 'ecb', 'cbc', 'cfb', or 'stream'.
    Raises:
        ValueError: if only 1 allowable byte is provided.
        RuntimeError: if it appears the oracle does not use a fixed IV, does not operate in a supported block cipher mode, or the oracle produces ciphertext of unexpected length.
    """
    if len(allowable_bytes) == 1:
        raise ValueError("Must specify more than one allowable byte.")
    
    if allowable_bytes:
        c = bytes([allowable_bytes[0]])
        d = bytes([allowable_bytes[1]])
    else:
        c = b'a'
        d = b'b'

    # First we need to check that a fixed plaintext encrypts to a fixed ciphertext.
    plaintext = c*block_size
    ciphertext = oracle(plaintext)
    if oracle(plaintext) != ciphertext:
        raise RuntimeError("Provided oracle appears to use randomised encryption. This function only supports deterministic encryption.")

    # Now craft a plaintext with repeated blocks to check for ECB mode.
    plaintext *= 10 # Don't actually need this many but just to be safe.
    ciphertext = oracle(plaintext)
    if evidence_of_ECB(ciphertext, block_size):
        return "ecb"

    # To distinguish between CBC, CFB and stream cipher modes we look at how the ciphertext changes after a one byte change in the plaintext. 
    #   - A stream cipher will always have exactly one byte that is different.
    #   - In CBC mode the block in which the change occurred and every block after that will be scrambled. In general every byte of the following blocks will change, but it is possible that some bytes remain the same through random chance. We expect that the number of bytes that change will be a multiple of the block size.
    #   - In CFB mode the block in which the change occurred will remain the same except for the byte that was altered, and every block after that will be scrambled. This usually means that the number of different bytes will be congruent to 1 modulo the block size. Again, this is not guaranteed however since some of the bytes in the remaining blocks could remain the same by chance.

    # We will send queries to the oracle in pairs constructed in the following way:
    #   - In both queries we pad out the blocks that contain the prefix with the same byte.
    #   - Then we construct two blocks that differ in exactly one byte.
    #   - We expect the last block to be a padding block.
    # So a pair of plaintext queries look like:
    #   pref|ixaa|aaaa|....
    #   pref|ixaa|baaa|....
    # Where "." represents padding added by the oracle, and "|" represents block boundaries.
    # We send multiple pairs where the byte that differs changes for each pair. So the next pair might look like:
    #   pref|ixaa|aaaa|....
    #   pref|ixaa|abaa|....

    # We want to minimise the number of blocks that are added as padding, thus reducing the number of blocks in which a byte could remain the same by chance.
    # In CBC mode with a block size of 16, there is approximately a 94% chance that a block of altered ciphertext has no bytes in common with corresponding block of unaltered ciphertext ( (255/256)^16 = 0.939 ). 
    # If we send 16 messages it is highly likely that one of them will produce the desired behaviour, allowing us to distinguish between CBC and CFB easily.

    prefix_fill_size = (block_size - prefix_length) % block_size
    max_bytes_diff = 0
    plaintext1 = c*(prefix_fill_size + block_size)
    ciphertext1 = oracle(plaintext1)
    for i in range(block_size):
        plaintext2 = c*prefix_fill_size + c*i + d + c*(block_size - 1 - i)
        ciphertext2 = oracle(plaintext2)
        bytes_diff = 0
        for x,y in zip(ciphertext1, ciphertext2):
            if x != y:
                bytes_diff += 1
        max_bytes_diff = max(max_bytes_diff, bytes_diff)
    
    # OFB is essentially a stream cipher so a change to one byte of the plaintext will leave all bytes of the ciphertext the same except for one.
    if max_bytes_diff == 1:
        return "stream"
    # In CBC changing a plaintext byte will change the entire block and everything after it. In CFB changing a plaintext byte will change the corresponding byte, leaving the rest of that block unchanged, and then change everything after that.
    elif max_bytes_diff % block_size == 0:
        return "cbc"
    elif max_bytes_diff % block_size == 1:
        return "cfb"
    else:
        raise RuntimeError("The provided oracle does not operate in one of the supported block cipher modes.")


def decrypt_suffix(
    oracle: Callable,
    suffix_len: int,
    prefix_len: int = 0,
    block_size: int = 16,
    allowable_bytes: Optional[bytes] = b'') -> bytes:
    """
    Decrypts the suffix added by the oracle to the plaintext prior to encryption.

    The oracle is assumed to take in a message of bytes, prepend a secret prefix, append a secret suffix, and then pad and encrypt the altered plaintext using a block cipher. If the oracle uses an IV it is assumed this is fixed and not included in the message.

    For example an oracle might take a message, prepend the string 'PPP', append the string 'SSS', pad to the appropriate length and then encrypt. Supposing the oracle used a block size of 4 bytes, the message 'abcd' is processed as follows:

    abcd -> PPPa|bcdS|SS.. -> ****|****|****

    Assuming the behaviour of the above described oracle, the idea behind this attack is as follows:
        1. We first construct a message long enough to pad out any blocks containing the prefix, and to contain the entire suffix. In this case we need one byte to pad out the blocks containing the prefix, and eight bytes (two blocks worth since the suffix could span at most two blocks) to contain the prefix. We can send any message we like of the required length eg:
        a|aaaa|aaaa -> PPPa|aaaa|aaaa|SSS. -> ****|****|****|****

        2. We then remove the first byte of the message and observe the oracle's reply, in particular the penultimate block:
        a|aaaa|aaa  -> PPPa|aaaa|aaaS|SS.. -> ****|****|&&&&|****
        
        3. We now loop through all possible bytes, appending them to the message and finding one that matches the observed ciphertext:
        a|aaaa|aaaS -> PPPa|aaaa|aaaS|SSS. -> ****|****|&&&&|****
        
        4. At this point we have found a match so we now the first byte of the suffix. We can return to step 2 to determine the next byte.

    Args:
        oracle: A block cipher encryption oracle with behaviour described above.
        suffix_len: The length of the secret suffix added.
        prefix_len: The length of the secret prefix added.
        block_size: The suspected block size of the underlying block cipher.
        allowable_bytes: A byte string consisting of bytes that are safe to send. Ones that won't be quoted out for example. By default it is assumed that all bytes are safe.
    Returns:
        The decrypted suffix that was added to the message.
    Raises:
        RuntimeError: If the provided oracle appears to use randomised encryption or if the function was unsuccessful in decrypting the suffix.
    """
    # Make sure bytes in allowable bytes are unique
    allowable_bytes = bytes(set(allowable_bytes))
    if allowable_bytes:
        a = bytes([allowable_bytes[0]])
    else:
        a = b'a'
        allowable_bytes = bytes(range(256))

    # Check for randomised encryption
    if oracle(a) != oracle(a):
        raise RuntimeError("Provided oracle appears to use randomised encryption. This function only supports deterministic encryption.")
    
    # Number of blocks taken up by the prefix:
    num_prefix_blocks = prefix_len // block_size + 1

    # To make life simple we fill out the prefix blocks if needed
    message = a * (num_prefix_blocks * block_size - prefix_len)
    # The maximum number of blocks needed to fit the suffix
    num_suffix_blocks = suffix_len // block_size + 1
    message += a * block_size * num_suffix_blocks
    suffix = b''

    for _ in range(suffix_len):
        # Pop off the first character
        message = message[1:]
        # First character of
        encrypted_blocks = bytes_to_blocks(oracle(message), block_size)
        target_block = encrypted_blocks[num_prefix_blocks + num_suffix_blocks - 1]
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
