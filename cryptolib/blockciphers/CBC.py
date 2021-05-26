from .Mode import Mode
from cryptolib.utils.byteops import block_xor, bytes_to_blocks

class CBCMode(Mode):
    """
    A block cipher in ECB mode.

    ECB mode encrypts and decrypts each block separately without the use of an IV or nonce.
    """

    def __init__(self, 
            algorithm: str,
            key: bytes, 
            IV: bytes, 
            padding: str = 'NoPadding'):
        super().__init__(algorithm, key, padding=padding)

        if IV and len(IV) != self.B:
            raise ValueError(f"IV must have length {self.B}. Got {len(IV)}.")
        self.IV = IV

    def encrypt(self, message: bytes, IV: bytes = None):
        if IV:
            self.IV = IV
        if not self.IV:
            raise ValueError("IV is required and none has been set.")
        if len(self.IV) != self.B:
            raise ValueError(f"IV must have length {self.B}. Got {len(IV)}.")
        
        padded_message = self.padder.pad(message)
        blocks = bytes_to_blocks(padded_message, self.B)
        cipher_blocks = [self.IV]
        for i, block in enumerate(blocks):
            cipher_in = block_xor(block, cipher_blocks[i])
            cipher_blocks.append(self._engine.encrypt(cipher_in))
        return b''.join(cipher_blocks[1:])
    
    def decrypt(self, ciphertext: bytes, IV: bytes = None):
        if (len(ciphertext) % self.B):
            raise ValueError(f"Length of ciphertext must be a multiple of {self.B}. Got {len(ciphertext)}.")
        
        if IV:
            self.IV = IV
        if not self.IV:
            raise ValueError("IV is required and none has been set.")
        if len(self.IV) != self.B:
            raise ValueError(f"IV must have length {self.B}. Got {len(IV)}.")

        plain = b''
        blocks = bytes_to_blocks(ciphertext, self.B)
        prev_block = self.IV
        for block in blocks:
            plain_block = block_xor(self._engine.decrypt(block), prev_block)
            prev_block = block
            plain += plain_block
        plain = self.padder.strip(plain)
        return plain
