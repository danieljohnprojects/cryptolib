from .Mode import Mode

class ECBMode(Mode):
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
        self._engine = (self.algorithms[algorithm])(key)
        self.B = self._engine.block_size
        self.pad = self.padding_methods[padding]

    def encrypt(self, message: bytes, IV: bytes = None) -> bytes:
        padded_message = self.pad(message, self.B)
        N = len(padded_message) // self.B
        # Separate message into blocks.
        blocks = [message[i*self.B:(i+1)*self.B] for i in range(N)]
        cipher_blocks = []
        for block in blocks:
            cipher_blocks.append(self._engine.encrypt(block))
        return b''.join(cipher_blocks)

    def decrypt(self, ciphertext: bytes, IV: bytes = None):
        if (len(ciphertext) % self.B):
            raise ValueError(f"Length of ciphertext must be a multiple of {self.B}. Got {len(ciphertext)}.")
        N = len(ciphertext) // self.B
        cipher_blocks = [ciphertext[i*self.B:(i+1)*self.B] for i in range(N)]
        plain_blocks = []
        for block in cipher_blocks:
            plain_blocks.append(self._engine.decrypt(block))
        return b''.join(plain_blocks)