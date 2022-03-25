"""
Attacks on generic block ciphers assuming the attacker has access to plaintext-ciphertext pairs coming from a generic block cipher.
"""

from typing import Callable


def exhaust_key(
        plaintext: bytes, 
        target_ciphertext: bytes, 
        encryption_oracle_constructor: Callable,
        keylength: int,
        nbits: int
    ) -> bytes:
    """
    Takes a plaintext-ciphertext pair and performs an nbit exhaust over the possible keys until one is found that encrypts the plaintext to the target_ciphertext.

    Obviously it is generally not practical to exhaust the entire keyspace. This function is probably most useful in the case that partial information is known about the key.

    Test keys will be big-endian byte strings of length keylength corresponding to the numbers ranging from 0 to 2^nbits - 1. The encryption_oracle_constructor can be defined so that the key is processed into another form before being used to instantiate the encryption oracle.

    Args:
        plaintext: Encrypted by each test encryption oracle.
        target_ciphertext: The goal ciphertext.
        encryption_oracle_constructor: A function that takes in a key byte string and returns another function that encrypts using the specified key.
        keylength: The length in bytes of the key.
        nbits: The number of bits to exhaust over.
    Returns:
        The key value that gave a matching encryption.
    Raises:
        RuntimeError: If no key was found. 
    """

    for test_key in range(2**nbits):
        test_key = test_key.to_bytes(keylength, 'big')
        cipher = encryption_oracle_constructor(test_key)
        if cipher(plaintext) == target_ciphertext:
            return test_key
    else:
        RuntimeError("No key found to ")