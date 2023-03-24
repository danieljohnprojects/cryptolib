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
        raise RuntimeError("No key found that produces a matching plaintext-ciphertext pair.")

def splice_ECB_ciphertext(
        plain_cipher_pairs: ((bytes, bytes), (bytes, bytes)),
        block_size: int,
    ) -> (bytes, bytes):
    """
    Given a collection of plaintext-ciphertext pairs originating from a block cipher in ECB mode we can construct a new pair by mixing the blocks of different messages together. 
    
    For example suppose the plaintexts:
       - "Please send: $15 to Alice."
       - "Please send: $0.05 to Bob."
    were encrypted with AES in ECB mode, and that we have the corresponding ciphertexts. We could then splice these together to get the encryption of:
         "Please send: $1505 to Bob."
    
    This function is likely not going to be particularly useful but hopefully it sparks your imagination if a similar opportunity present itself.
    
    Usage:
        import secrets
        from cryptolib.blockciphers.chosen_plain.oracles import EncryptECB
        key = secrets.token_bytes(16)
        enc = EncryptECB('aes', key)
        dec = DecryptECB('aes', key)
        p1 = b'Please send: $15 to Alice.'
        p2 = b'Please send: $0.05 to Bob.'
        c1 = enc(p1)
        c2 = enc(p2)
        p3, c3 = splice_ECB_ciphertext( ((p1, c1), (p2, c2)), 16 )
        assert enc(p3) == c3
        
    Args:
        plain_cipher_pairs: A tuple containing two plaintext-ciphertext pairs.
        block_size: The block size of the underlying cipher.
    Returns:
        A new plaintext-ciphertext pair spliced from the old ones.
    """
    p1 = plain_cipher_pairs[0][0]
    c1 = plain_cipher_pairs[0][1]
    p2 = plain_cipher_pairs[1][0]
    c2 = plain_cipher_pairs[1][1]
    
    splicedP = p1[:block_size] + p2[block_size:]
    splicedC = c1[:block_size] + c2[block_size:]
    return splicedP, splicedC