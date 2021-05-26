from .Mode import Mode
from cryptolib.utils.byteops import bytes_to_blocks

class ECBMode(Mode):
    """
    A block cipher in ECB mode.

    ECB mode encrypts and decrypts each block separately without the use of an IV or nonce.
    """

    def __init__(self, 
            algorithm: str,
            key: bytes,
            padding: str = 'NoPadding'):
        super().__init__(algorithm, key, padding=padding)

    def encrypt(self, message: bytes) -> bytes:
        padded_message = self.padder.pad(message)
        blocks = bytes_to_blocks(padded_message, self.B)
        cipher_blocks = []
        for block in blocks:
            cipher_blocks.append(self._engine.encrypt(block))
        return b''.join(cipher_blocks)

    def decrypt(self, ciphertext: bytes):
        if (len(ciphertext) % self.B):
            raise ValueError(f"Length of ciphertext must be a multiple of {self.B}. Got {len(ciphertext)}.")
        cipher_blocks = bytes_to_blocks(ciphertext, self.B)
        plain = b''
        for block in cipher_blocks:
            plain += self._engine.decrypt(block)
        plain = self.padder.strip(plain)
        return plain