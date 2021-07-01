import pytest
import secrets
from cryptolib import oracles

from cryptolib.cracks.bc_oracles import (
    uses_ECB, 
    get_block_size, 
    get_additional_message_len, 
    decode_suffix
)
from cryptolib.oracles import (
    Oracle, 
    ECB_CBC_oracle, 
    AdditionalPlaintextOracle, 
    AdditionalPlaintextWithQuotingOracle
)
from cryptolib.pipes import StripPKCS7Pipe, PadPKCS7Pipe, BCDecryptPipe
from cryptolib.utils.byteops import bytes_to_blocks, block_xor
from cryptolib.utils.conversion import b64_string_to_hex
from cryptolib.utils.padding import PaddingError, pkcs7

from .oracles import challenge13, challenge16
from .data import challenge10, challenge12

def test_Challenge09():
    """
    A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

    One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

    So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance, 

    "YELLOW SUBMARINE"

    ... padded to 20 bytes would be:

    "YELLOW SUBMARINE\\x04\\x04\\x04\\x04"
    """

    oracle = Oracle([PadPKCS7Pipe(block_size=20)])

    test_in = bytes(b"YELLOW SUBMARINE")
    solution = bytes(b"YELLOW SUBMARINE\x04\x04\x04\x04")

    assert oracle.divine(test_in) == solution

def test_Challenge10():
    """
    CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

    In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

    The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

    Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

    The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\\x00\\x00\\x00 &c) 
    """
    ciphertext = bytes.fromhex(b64_string_to_hex(challenge10.ciphertext))
    solution = challenge10.solution
    key = b'YELLOW SUBMARINE'

    oracle = Oracle([
        BCDecryptPipe('cbc', 'aes', key, iv=bytes(16)),
        StripPKCS7Pipe()
    ])
    assert oracle.divine(ciphertext) == solution

def test_Challenge11():
    """
    Now that you have ECB and CBC working:

    Write a function to generate a random AES key; that's just 16 random bytes.

    Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

    The function should look like:

    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]

    Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

    Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

    Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening. 
    """
    oracle = ECB_CBC_oracle()
    for _ in range(10):
        mode = 'ECB' if uses_ECB(oracle) else 'CBC'
        assert oracle._last_choice == mode

def test_Challenge12():
    """
    Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

    Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK

    Spoiler alert.

    Do not decode this string now. Don't do it.

    Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

    What you have now is a function that produces:

    AES-128-ECB(your-string || unknown-string, random-key)

    It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

    Here's roughly how:

        Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
        Detect that the function is using ECB. You already know, but do this step anyways.
        Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
        Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
        Repeat for the next byte.
    """
    solution = bytes.fromhex(b64_string_to_hex( challenge12.secret_suffix_b64 ))
    oracle = AdditionalPlaintextOracle(secret_suffix=solution)
    B = get_block_size(oracle)
    assert(uses_ECB(oracle, block_size=B))
    _, suffix_len = get_additional_message_len(oracle, B)
    suffix = decode_suffix(oracle, suffix_len, block_size=B)
    assert suffix == solution

def test_Challenge13():
    allowable_bytes = \
        bytes(range(0,ord('&'))) \
        + bytes(range(ord('&'), ord('='))) \
        + bytes(range(ord('='), 256))

    server, client = challenge13.create_server_client()
    B = get_block_size(client, allowable_bytes=allowable_bytes)
    assert(uses_ECB(client, B, allowable_bytes=allowable_bytes))
    prefix_len, suffix_len = get_additional_message_len(client, B, allowable_bytes=allowable_bytes)
    # Can't actually decode suffix since it contains characters that we cannot send through the oracle.

    # Need to figure out what a block consisting of the string "admin" looks like encrypted.
    desired_role = pkcs7(b'admin', B)
    # First need to fill out the blocks containing the prefix
    N = (prefix_len // B + 1) * B - prefix_len
    message = N*b'a' + desired_role
    cipherblocks = bytes_to_blocks(client.divine(message), B)
    encrypted_role = cipherblocks[prefix_len // B + 1]

    # Now just get a user who's role lies on the edge of a block.
    # Want the total message to look like:
    # |prefix.userd|etails.role=|user........|
    L = prefix_len + suffix_len - len(b'user')
    user_details_len = (L // B + 1) * B - L
    message = b'a' * user_details_len
    cipherblocks = bytes_to_blocks(client.divine(message), B)
    # Replace the user role with the admin role
    cipherblocks[-1] = encrypted_role

    assert server.divine(b''.join(cipherblocks)) == b'admin'

def test_Challenge14():
    """
    Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

    Same goal: decrypt the target-bytes. 
    """
    solution = secrets.token_bytes(secrets.choice(range(6,20)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secrets.token_bytes(secrets.choice(range(6, 20))),
        secret_suffix=solution
    )

    B = get_block_size(oracle)
    assert(uses_ECB(oracle, block_size=B))
    prefix_len, suffix_len = get_additional_message_len(oracle, B)
    assert decode_suffix(oracle, suffix_len, prefix_len, B) == solution

def test_Challenge15():
    """
    Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

    The string:

    "ICE ICE BABY\x04\x04\x04\x04"

    ... has valid padding, and produces the result "ICE ICE BABY".

    The string:

    "ICE ICE BABY\x05\x05\x05\x05"

    ... does not have valid padding, nor does:

    "ICE ICE BABY\x01\x02\x03\x04"

    If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

    Crypto nerds know where we're going with this. Bear with us. 
    """

    oracle = Oracle([StripPKCS7Pipe(block_size=16)])

    test_values = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04"
    ]

    assert oracle.divine(test_values[0]) == b"ICE ICE BABY"
    try:
        oracle.divine(test_values[1])
    except PaddingError:
        assert True
    else:
        assert False
    try:
        oracle.divine(test_values[2])
    except PaddingError:
        assert True
    else:
        assert False

def test_Challenge16():
    """
    Generate a random AES key.

    Combine your padding code and CBC code to write two functions.

    The first function should take an arbitrary input string, prepend the string:

    "comment1=cooking%20MCs;userdata="

    .. and append the string:

    ";comment2=%20like%20a%20pound%20of%20bacon"

    The function should quote out the ";" and "=" characters.

    The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

    The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

    Return true or false based on whether the string exists.

    If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

    Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

    You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.
    """
    server, client = challenge16.create_server_client()

    allowable_bytes = bytes(set(range(256)) - {ord(';'), ord('=')})
    B = get_block_size(client, allowable_bytes=allowable_bytes)
    prefix_len, _ = get_additional_message_len(client, B, allowable_bytes)
    # We want our message to decrypt to 
    target_message = b';admin=true'
    # To do so we will send the string
    send_message = b':admin<true'
    # Fill up the blocks containing the prefix, plus an extra block
    # The extra block will get scrambled when we flip some bits
    # So we want it to look like:
    # |{prefix}****|************|:admin<true{|suffix}*****|
    # We need this extra block just in case there prefix ends at the end of the 
    # block. We only want to scramble blocks containing our input.
    N = (B - (prefix_len % B))
    fill = bytes([allowable_bytes[0]])
    usr_input = fill * (N + B) + send_message

    enc_input = client.divine(usr_input)

    mask = block_xor(target_message, send_message)
    # Pad the mask to size B with 0s
    mask += b'\x00' * ((B - (len(mask) % B)) % B)
    # If the target message is longer than the block size this won't work
    assert len(mask) == B
    # Find the block just before the one containing the target message
    target_block = enc_input[prefix_len + N : prefix_len + N + B]
    replacement_block = block_xor(mask, target_block)
    altered_enc  = enc_input[:prefix_len + N]       \
                   + replacement_block              \
                   + enc_input[prefix_len + N + B:]
    
    assert server.divine(altered_enc) == b'true'