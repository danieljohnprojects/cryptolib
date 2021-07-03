from .ECBEncrypt import ECBEncrypt

from ..utils.byteops import block_xor, bytes_to_blocks


class CBCEncrypt(ECBEncrypt):
    def __call__(self, message: bytes) -> bytes:
        """
        Encrypts a message in CBC mode, treating the first block as an IV. 
        
        Messages should be a multiple of the block size in length.
        """
        message_blocks = bytes_to_blocks(message, self.state['block_size'])
        if len(message_blocks) < 2:
            raise ValueError(f"Need at least two blocks (one of IV, one of data) to encrypt in CBC mode, got {len(message_blocks)}.")
        
        # First block is treated as IV
        cipher_blocks = [message_blocks[0]]
        for block in message_blocks[1:]:
            cipher_input = block_xor(block, cipher_blocks[-1])
            cipher_blocks.append(self.state['engine'].encrypt(cipher_input))
        return b''.join(cipher_blocks)
