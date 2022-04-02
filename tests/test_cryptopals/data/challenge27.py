import secrets

from cryptolib.blockciphers.chosen_cipher.oracles import DecryptCBC_key_as_iv
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC_key_as_iv

def create_server_client():
    key = secrets.token_bytes(16)
    
    client = EncryptCBC_key_as_iv('aes', key)
    
    class server:
        def __init__(self):
            self.engine = DecryptCBC_key_as_iv('aes', key)
        def __call__(self, ciphertext: bytes) -> bytes:
            message = self.engine(ciphertext)
            if not message.isascii():
                raise ValueError(f"Message {message} contains non-ascii characters!")
            
    return server(), client
