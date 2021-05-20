from .Mode import Mode
from cryptolib.utils.byteops import block_xor

class CBCMode(Mode):
    """
    A block cipher in ECB mode.

    ECB mode encrypts and decrypts each block separately without the use of an IV or nonce.
    """

    def __init__(self, 
        algorithm: str,
        key: bytes, 
        IV: bytes = bytes(b''), 
        nonce: bytes = bytes(b''),
        padding: str = 'NoPadding'):
        self._engine = (self._algorithms[algorithm])(key)
        self.B = self._engine.block_size
        self.pad = self._padding_methods[padding]
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
        
        padded_message = self.pad(message, self.B)
        N = len(padded_message) // self.B
        # Separate message into blocks.
        blocks = [padded_message[i*self.B:(i+1)*self.B] for i in range(N)]
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

        plain_blocks = []
        N = len(ciphertext) // self.B
        blocks = [ciphertext[i*self.B:(i+1)*self.B] for i in range(N)]
        prev_block = self.IV
        for block in blocks:
            plain = block_xor(self._engine.decrypt(block), prev_block)
            prev_block = block
            plain_blocks.append(plain)

        return b''.join(plain_blocks)
