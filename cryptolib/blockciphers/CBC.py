from typing import Optional, Sequence
from .Mode import Mode
from cryptolib.utils.byteops import block_xor, bytes_to_blocks

class CBCMode(Mode):
    """A block cipher in CBC mode.

    In CBC mode each block of ciphertext is xored onto the plaintext prior to encryption with the block cipher. For the first block of plaintext an iv is used instead of a ciphertext block.
    """

    def __init__(self, 
            algorithm: str,
            key: bytes, 
            iv: Optional[bytes] = None):
        """
        Initialises the block cipher with the given algorithm, key, and iv.

        Arguments:
            algorithm
                The algorithm to use for the underlying engine. Passed as a string (case insensitive).
            key
                The key to use when encrypting.
            iv
                The iv to use in the next encryption or decryption call. If none is given it is assumed one will be provided at the time of en/decryption.
        """
        super().__init__(algorithm, key)

        if iv and len(iv) != self.block_size:
            raise ValueError(f"iv must have length {self.block_size}. Got {len(iv)}.")
        self.iv = iv

    def encrypt(self, 
            message_blocks: Sequence[bytes], 
            iv: Optional[bytes] = None
            ) -> Sequence[bytes]:
        if iv:
            self.iv = iv
        if not self.iv:
            raise ValueError("iv is required and none has been set.")
        if len(self.iv) != self.block_size:
            raise ValueError(f"iv must have length {self.block_size}. Got {len(iv)}.")
        
        cipher_blocks = [self.iv]
        for block in message_blocks:
            cipher_in = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self._engine.encrypt(cipher_in))
        return cipher_blocks[1:]
    
    def decrypt(self, 
            cipher_blocks: Sequence[bytes], 
            iv: Optional[bytes] = None
            ) -> Sequence[bytes]:
        # if (len(ciphertext) % self.B):
        #     raise ValueError(f"Length of ciphertext must be a multiple of {self.B}. Got {len(ciphertext)}.")
        
        if iv:
            self.iv = iv
        if not self.iv:
            raise ValueError("iv is required and none has been set.")
        if len(self.iv) != self.block_size:
            raise ValueError(f"iv must have length {self.block_size}. Got {len(iv)}.")

        plain_blocks = []
        prev_block = self.iv
        for block in cipher_blocks:
            plain_block = block_xor(self._engine.decrypt(block), prev_block)
            plain_blocks.append(plain_block)
            prev_block = block
        return plain_blocks
