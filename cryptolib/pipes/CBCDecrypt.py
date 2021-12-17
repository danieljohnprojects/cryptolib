from .ECBDecrypt import ECBDecrypt

from ..utils.byteops import block_xor, bytes_to_blocks


class CBCDecrypt(ECBDecrypt):
    """
    A pipe that decrypts strings of bytes using the specified algorithm in CBC mode.

    The first block of the message string is used as the IV.
    """

    def __call__(self, message: bytes) -> bytes:
        """
        Decrypts a message in CBC mode, treating the first block as an IV.

        Returns the plain text sans iv.
        """
        message_blocks = bytes_to_blocks(message, self.state['block_size'])
        if len(message_blocks) < 2:
            raise ValueError(f"Need at least two blocks (one of IV, one of data) to decrypt in CBC mode, got {len(message_blocks)}.")

        plain_blocks = []
        prev_block = message_blocks[0]
        for block in message_blocks[1:]:
            plain_block = block_xor(self.state['engine'].decrypt(block), prev_block)
            plain_blocks.append(plain_block)
            prev_block = block

        return b''.join(plain_blocks)
