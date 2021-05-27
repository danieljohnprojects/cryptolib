from typing import Tuple
from cryptolib.blockciphers import ECBMode
from cryptolib.oracles import Oracle, AdditionalPlaintextOracle

import secrets

class client(AdditionalPlaintextOracle):
    def __init__(self, key: bytes):
        super().__init__(
            secret_prefix=b'email=', 
            secret_suffix=b'&UID=10&role=user', 
            mode='ecb', 
            algorithm='AES', 
            padding='pkcs7', 
            key=key)

    def divine(self, message: bytes) -> bytes:
        if b'&' in message or b'=' in message:
            raise ValueError("Usermail cannot contain the characters '&' or '='")
        return super().divine(message)

class server(Oracle):
    def __init__(self, key: bytes):
        self._ecb = ECBMode("AES", key, padding="pkcs7")
    
    def _str_to_dict(self, s: str) -> dict:
        """
        Takes in a string of the form "foo=bar&baz=qux&zap=zazzle" and produces a dictionary of the form 
        {foo: 'bar', baz: 'qux', zap: 'zazzle'}.
        """
        pairs = s.split('&')
        pairs = [ pair.split('=') for pair in pairs ]
        return { pair[0]:pair[1] for pair in pairs }
    
    def divine(self, message: bytes) -> bytes:
        """
        Takes in an encrypted user profile and returns the role of the user.
        """
        profile_str = self._ecb.decrypt(message).decode("ascii")
        profile = self._str_to_dict(profile_str)
        return profile['role']

def create_server_client() -> Tuple[server, client]:
    key = secrets.token_bytes(32)
    return server(key), client(key)