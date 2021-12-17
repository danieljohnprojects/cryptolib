from .ECBEncrypt import ECBEncrypt

from ..utils.byteops import block_xor, bytes_to_blocks

class CTR(ECBEncrypt):
    """
    A pipe that encrypts strings of bytes using the specified algorithm in CTR mode.

    Messages must be prefixed with a nonce of appropriate length.
    """

    def __init__(self, 
                *args, 
                nonce_size=8, 
                ctr_endianness: str = 'little', 
                **kwargs):

        super().__init__(*args, **kwargs)
        block_size = self.state['block_size']
        if nonce_size < 1 or nonce_size >= block_size:
            raise ValueError(f"nonce_size must be between 1 and block_size-1 ({block_size - 1}) inclusive. Got {nonce_size}.")
        if ctr_endianness not in ['little', 'big']:
            raise ValueError(f"ctr_endianness must be either little or big. Got {ctr_endianness}.")
        
        self.state['ctr_endianness'] = ctr_endianness
        self.state['nonce_size'] = nonce_size
        self.state['max_message_len'] = pow(2, 8*(block_size - nonce_size))

    def __call__(self, message: bytes) -> bytes:
        """
        Encrypts a message in CTR mode, treating the first few bytes as a nonce.

        The size of the nonce is determined by the nonce_size parameter in the object's state dictionary.
        """
        nonce_size = self.state['nonce_size']
        block_size = self.state['block_size']
        max_message_len = self.state['max_message_len']
        engine = self.state['engine']
        endianness = self.state['ctr_endianness']

        nonce = message[:nonce_size]
        message_blocks = bytes_to_blocks(message[nonce_size:], block_size)

        if len(message_blocks) > max_message_len:
            raise ValueError("Message too long to encrypt without repeating IV!")
        
        cipher_blocks = []
        for block_count, block in enumerate(message_blocks):
            iv = nonce + block_count.to_bytes(block_size - nonce_size, endianness)
            cipher_block = block_xor(engine.encrypt(iv)[:len(block)], block)
            cipher_blocks.append(cipher_block)
        
        return b''.join(cipher_blocks)