import secrets

from math import ceil
from typing import Callable, Optional, Tuple

from ..algorithms import engine_generators
from ...hashes.MAC import HMAC
from ...hashes.SHA2 import sha224digest
from ...utils.byteops import block_xor, bytes_to_blocks
from ...utils.padding import pkcs7, strip_pkcs7

encryptor = Callable[[bytes], bytes]
decryptor = Callable[[bytes], bytes]


def ECBoracle(algorithm: str, key: Optional[bytes] = None) -> Tuple[encryptor, decryptor]:
    """Returns a pair of oracles that encrypt and decrypt in ECB mode under a fixed key.

    Args:
        algorithm (str): The block cipher algorithm to use. For example 'aes'.
        key (Optional[bytes], optional): The key to use. If no key is given a random one is generated. Defaults to None.

    Returns:
        Tuple[encryptor, decryptor]: The pair of oracles.
    """
    engine_generating_function, key_size = engine_generators[algorithm.lower()]
    if not key:
        key = secrets.token_bytes(key_size)
    engine = engine_generating_function(key)
    block_size = engine.block_size

    def encrypt(message: bytes) -> bytes:
        message = pkcs7(message, block_size)
        message_blocks = bytes_to_blocks(message, block_size)
        cipher_blocks = map(engine.encrypt, message_blocks)
        return b''.join(cipher_blocks)

    def decrypt(message: bytes) -> bytes:
        cipher_blocks = bytes_to_blocks(message, block_size)
        plain_blocks = map(engine.decrypt, cipher_blocks)
        plain = b''.join(plain_blocks)
        return strip_pkcs7(plain, block_size)

    return encrypt, decrypt


def cbc_oracle_builder(
        engine_generating_function,
        key: bytes,
        iv_generator: Callable[[], bytes],
        include_iv_in_ciphertext: bool) -> Tuple[encryptor, decryptor]:
    engine = engine_generating_function(key)
    block_size = engine.block_size

    def encrypt(message: bytes) -> bytes:
        message = pkcs7(message, block_size)
        message_blocks = bytes_to_blocks(message, block_size)
        cipher_blocks = [iv_generator()]
        for block in message_blocks:
            cipher_input = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(engine.encrypt(cipher_input))
        if not include_iv_in_ciphertext:
            cipher_blocks = cipher_blocks[1:]
        return b''.join(cipher_blocks)

    def decrypt(message: bytes) -> bytes:
        if not include_iv_in_ciphertext:
            message = iv_generator() + message
        cipher_blocks = bytes_to_blocks(message, block_size)
        cipher_output = map(engine.decrypt, cipher_blocks[1:])
        plain_blocks = [block_xor(c_block, out_block) for c_block, out_block in zip(
            cipher_blocks[:-1], cipher_output)]
        message = b''.join(plain_blocks)
        return strip_pkcs7(message, block_size)

    return encrypt, decrypt


def CBCoracle(algorithm: str, key: Optional[bytes] = None) -> Tuple[encryptor, decryptor]:
    """Constructs a pair of AES encryption and decryption oracles that operate in CBC mode under a fixed key.

    Note that the encryption oracle automatically prepends a randomly generated IV to the ciphertext.
    The decryption oracle uses the first block of the ciphertext as the IV.

    The decryption oracle raises a PaddingError if the resulting plaintext has incorrect padding.
    This can be exploited in a CBC padding oracle attack if it is not handled correctly.

    Args:
        algorithm (str): The algorithm used for encryption and decryption.
        key (Optional[bytes], optional): The key to use. If no key is given one is generated randomly. Defaults to None.

    Returns:
        Tuple[encryptor, decryptor]: The encryption and decryption oracles.
    """
    engine_generating_function, keysize = engine_generators[algorithm]
    if not key:
        key = secrets.token_bytes(keysize)
    enc, dec = cbc_oracle_builder(
        engine_generating_function, key, lambda: secrets.token_bytes(16), True)
    return enc, dec


def CBCoracle_KeyAsIV(key: Optional[bytes] = None) -> Tuple[encryptor, decryptor]:
    """Constructs an AES encryption and decryption oracle pair that operate in CBC mode using a fixed byte string as both the key and IV.

    Args:
        key (Optional[bytes], optional): The key to use for encryption and decryption. If no key is given one is generated at random. Defaults to None.

    Returns:
        Tuple[encryptor, decryptor]: The encryption and decryption oracles.
    """
    engine_generating_function, keysize = engine_generators['aes']
    if not key:
        key = secrets.token_bytes(keysize)
    enc, dec = cbc_oracle_builder(
        engine_generating_function, key, lambda: key, False)
    return enc, dec


def CBCoracle_FixedIV(key: Optional[bytes] = None, iv: Optional[bytes] = None) -> Tuple[encryptor, decryptor]:
    """Constructs an encryption and decryption oracle pair that operate in CBC mode using a fixed key and a fixed (secret) iv.

    Args:
        key (Optional[bytes], optional): The key to use for encryption and decryption. If no key is given one is generated at random. Defaults to None.
        iv (Optional[bytes], optional): The iv to use for encryption and decryption. If no iv is given one is generated at random. Defaults to None.

    Returns:
        Tuple[encryptor, decryptor]: The encryption and decryption oracles.
    """
    engine_generating_function, keysize = engine_generators['aes']
    if not key:
        key = secrets.token_bytes(keysize)
    if not iv:
        iv = secrets.token_bytes(16)
    enc, dec = cbc_oracle_builder(
        engine_generating_function, key, lambda: iv, False)
    return enc, dec


# def CTRHMACoracle(bc_algorithm: str, key: Optional[bytes] = None) -> Tuple[encryptor, decryptor]:
#     engine_generating_function, key_size = engine_generators[bc_algorithm.lower(
#     )]
#     if not key:
#         key = secrets.token_bytes(key_size)
#     engine = engine_generating_function(key)
#     block_size = engine.block_size
#     nonce = 0
#     nonce_size = block_size // 2
#     ctr_size = block_size - nonce_size

#     hmac_size = 28
#     sign, verify = HMAC(sha224digest, key)

#     def encrypt(message: bytes) -> bytes:
#         nBlocks = ceil(len(message) / block_size)
#         nonce_bytes = nonce.to_bytes(nonce_size, "big")
#         keystream = [nonce_bytes +
#                      i.to_bytes(ctr_size, "big") for i in range(nBlocks)]
#         keystream = b''.join(map(engine.encrypt, keystream))
#         keystream = keystream[:len(message)]
#         cipher = nonce_bytes + block_xor(keystream, message)
#         hmac = sign(cipher)
#         nonce += 1
#         return cipher + hmac

#     def decrypt(message: bytes) -> bytes:
#         hmac = message[-hmac_size:]
#         message = message[:-hmac_size]
#         if not verify(message, hmac):
#             return b""

#         pass

#     return encrypt, decrypt
