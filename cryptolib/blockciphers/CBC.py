from typing import Optional, Sequence
from .Mode import Mode
from cryptolib.utils.byteops import block_xor, bytes_to_blocks

class CBCMode(Mode):
    """A block cipher in CBC mode.

    In CBC mode each block of ciphertext is xored onto the plaintext prior to encryption with the block cipher. For the first block of plaintext an IV is used instead of a ciphertext block.
    """

    def __init__(self, 
            algorithm: str,
            key: bytes, 
            IV: Optional[bytes] = None):
        """
        Initialises the block cipher with the given algorithm, key, and IV.

        Arguments:
            algorithm
                The algorithm to use for the underlying engine. Passed as a string (case insensitive).
            key
                The key to use when encrypting.
            IV
                The IV to use in the next encryption or decryption call. If none is given it is assumed one will be provided at the time of en/decryption.
        """
        super().__init__(algorithm, key)

        if IV and len(IV) != self.block_size:
            raise ValueError(f"IV must have length {self.block_size}. Got {len(IV)}.")
        self.IV = IV

    def encrypt(self, 
            message_blocks: Sequence[bytes], 
            IV: Optional[bytes] = None
            ) -> Sequence[bytes]:
        if IV:
            self.IV = IV
        if not self.IV:
            raise ValueError("IV is required and none has been set.")
        if len(self.IV) != self.block_size:
            raise ValueError(f"IV must have length {self.block_size}. Got {len(IV)}.")
        
        cipher_blocks = [self.IV]
        for block in message_blocks:
            cipher_in = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_in))
        return cipher_blocks[1:]
    
    def decrypt(self, 
            cipher_blocks: Sequence[bytes], 
            IV: Optional[bytes] = None
            ) -> Sequence[bytes]:
        # if (len(ciphertext) % self.B):
        #     raise ValueError(f"Length of ciphertext must be a multiple of {self.B}. Got {len(ciphertext)}.")
        
        if IV:
            self.IV = IV
        if not self.IV:
            raise ValueError("IV is required and none has been set.")
        if len(self.IV) != self.block_size:
            raise ValueError(f"IV must have length {self.block_size}. Got {len(IV)}.")

        plain_blocks = []
        prev_block = self.IV
        for block in cipher_blocks:
            plain_block = block_xor(self._engine.decrypt(block), prev_block)
            plain_blocks.append(plain_block)
            prev_block = block
        return plain_blocks
