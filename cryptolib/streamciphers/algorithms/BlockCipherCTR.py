from math import ceil
from ...blockciphers.algorithms import engine_generators
from ...utils.byteops import block_xor


class BlockCipherCTR:
    """
    
    """
    def __init__(self, algorithm: str, key: bytes, nonce_size: int, ctr_endianness: str = 'big'):
        """
        Initialises a stream cipher using a block cipher in CTR mode.

        Args:
            algorithm: The block cipher algorithm to be used.
            key: The private key used to instantiate the block cipher.
            nonce_size: The size of the nonce in bytes used to encrypt messages.
        Raises:
            ValueError: If invalid nonce size is given.
        """
        eng_gen = engine_generators[algorithm][0]
        self._engine = eng_gen(key)
        if nonce_size < 1 or (nonce_size >= self._engine.block_size):
            raise ValueError(f"Nonce must be in range [1, {self._engine.block_size - 1}]. Got {nonce_size}.")
        self.nonce_size = nonce_size
        self.max_message_blocks = pow(2, (self._engine.block_size - self.nonce_size) * 8)
        self.nonce = 0
        self._nonce_has_wrapped = False
        self.ctr_endianness = ctr_endianness

    def encrypt(self, message: bytes) -> bytes:
        """
        Encrypts a given message and returns the nonce plus ciphertext.

        Args:
            message: the message to be encrypted.
        Returns:
            The nonce used plus the ciphertext.
        Raises:
            ValueError: if the provided message is too long for the given nonce size.
            RuntimeError: if the nonce has wrapped around, leaving further encryption impossible without breaking confidentiality.
        """
        if self._nonce_has_wrapped:
            raise RuntimeError("Too many messages have been encrypted using this key. Any further use of this cipher could result in a break in confidentiality. To continue encrypting message instantiate another cipher, perhaps with a larger nonce.")

        nblocks = ceil(len(message) / self._engine.block_size)
        if nblocks > self.max_message_blocks:
            raise ValueError(f"Message of {len(message)} bytes is too long to encrypt. With nonce size of {self.nonce_size} the maximum message length is {self.max_message_blocks * self._engine.block_size}.")

        nonce_bytes = self.nonce.to_bytes(self.nonce_size, 'big')
        keystream = [ nonce_bytes + i.to_bytes(self._engine.block_size - self.nonce_size, self.ctr_endianness) for i in range(nblocks)]
        keystream = map(self._engine.encrypt, keystream)
        keystream = b''.join(keystream)
        keystream = keystream[:len(message)]

        ciphertext = block_xor(keystream, message)

        ciphertext = self.nonce.to_bytes(self.nonce_size, 'big') + ciphertext

        self.nonce += 1
        if self.nonce >= pow(2, self.nonce_size * 8):
            self._nonce_has_wrapped = True 

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce_bytes = ciphertext[:self.nonce_size]
        ciphertext = ciphertext[self.nonce_size:]

        nblocks = ceil(len(ciphertext) / self._engine.block_size)
        if nblocks > self.max_message_blocks:
            raise ValueError(f"Ciphertext of {len(ciphertext)} bytes is too long to decrypt. With nonce size of {self.nonce_size} the maximum message length is {self.max_message_blocks * self._engine.block_size}.")

        keystream = [ nonce_bytes + i.to_bytes(self._engine.block_size - self.nonce_size, self.ctr_endianness) for i in range(nblocks) ]
        keystream = map(self._engine.encrypt, keystream)
        keystream = b''.join(keystream)
        keystream = keystream[:len(ciphertext)]

        return block_xor(keystream, ciphertext)