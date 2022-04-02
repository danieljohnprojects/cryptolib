"""
A collection of block cipher oracles including some misimplementations that can be attacked with chosen plaintext attacks.
"""

import secrets

from typing import Optional

from ..algorithms import engine_generators
from ...utils.byteops import block_xor, bytes_to_blocks
from ...utils.padding import pkcs7

class EncryptECB:
    """
    An oracle that encrypts the supplied string of bytes using the specified algorithm and an optional key in ECB mode.

    Messages will be padded out to a multiple of the block size using pkcs7 padding.
    """

    def __init__(self,
                 algorithm: str,
                 key: Optional[bytes] = None):

        engine_generating_function, key_size = engine_generators[algorithm.lower()]
        if not key:
            key = secrets.token_bytes(key_size)
        self._engine = engine_generating_function(key)
        self._block_size = self._engine.block_size

    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        cipher_blocks = []
        for block in message_blocks:
            cipher_blocks.append(self._engine.encrypt(block))
        return b''.join(cipher_blocks)


class EncryptCBC(EncryptECB):
    """
    An oracle that encrypts the supplied string of bytes using the specified algorithm, an optional key, and a randomly generated initialisation vector in CBC mode. Ciphertext will be returned with the IV at the beginning.

    Messages will be padded out to a multiple of the block size using pkcs7 padding.
    """
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [secrets.token_bytes(self._block_size)]

        for block in message_blocks:
            cipher_input = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_input))
        return b''.join(cipher_blocks)


class EncryptCFB(EncryptECB):
    """
    An oracle that encrypts the supplied string of bytes using the specified algorithm, an optional key, and a randomly generated initialisation vector in CFB mode. Ciphertext will be returned with the IV at the beginning.

    Messages will be padded out to a multiple of the block size using pkcs7 padding.
    """
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [secrets.token_bytes(self._block_size)]

        for block in message_blocks:
            cipher_output = self._engine.encrypt(cipher_blocks[-1])
            cipher_blocks.append(block_xor(block, cipher_output))
        return b''.join(cipher_blocks)


class EncryptOFB(EncryptECB):
    """
    An oracle that encrypts the supplied string of bytes using the specified algorithm, an optional key, and a randomly generated initialisation vector in OFB mode. Ciphertext will be returned with the IV at the beginning.

    Messages will be padded out to a multiple of the block size using pkcs7 padding.
    """
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [secrets.token_bytes(self._block_size)]

        cipher_output = cipher_blocks[0]
        for block in message_blocks:
            cipher_output = self._engine.encrypt(cipher_output)
            cipher_blocks.append(block_xor(block, cipher_output))
        return b''.join(cipher_blocks)


class EncryptCBC_fixed_iv(EncryptECB):
    def __init__(self, 
                 algorithm: str, 
                 key: Optional[bytes] = None, 
                 iv: Optional[bytes] = None):
        super().__init__(algorithm, key)
        if not iv:
            iv = secrets.token_bytes(self._block_size)
        self._iv = iv
    
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [self._iv]

        for block in message_blocks:
            cipher_input = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_input))
        return b''.join(cipher_blocks)


class EncryptCFB_fixed_iv(EncryptCBC_fixed_iv):
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [self._iv]

        for block in message_blocks:
            cipher_output = self._engine.encrypt(cipher_blocks[-1])
            cipher_blocks.append(block_xor(block, cipher_output))
        return b''.join(cipher_blocks)


class EncryptOFB_fixed_iv(EncryptCBC_fixed_iv):
    def __call__(self, message: bytes) -> bytes:
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [self._iv]

        cipher_output = cipher_blocks[0]
        for block in message_blocks:
            cipher_output = self._engine.encrypt(cipher_output)
            cipher_blocks.append(block_xor(block, cipher_output))
        return b''.join(cipher_blocks)


class EncryptCBC_key_as_iv(EncryptCBC):
    def __call__(self, message: bytes) -> bytes:
        key = self._engine._key_schedule[:self._block_size]
        message = pkcs7(message, self._block_size)
        message_blocks = bytes_to_blocks(message, self._block_size)
        
        cipher_blocks = [key]

        for block in message_blocks:
            cipher_input = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_input))
        return b''.join(cipher_blocks[1:])