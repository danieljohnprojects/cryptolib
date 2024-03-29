from cryptolib.streamciphers.algorithms import BlockCipherCTR

import re
import secrets


def parse_dict(message: bytes):
    """
    Takes in a string of the form "foo=bar&baz=qux&zap=zazzle" and produces a dictionary of the form 
    {foo: 'bar', baz: 'qux', zap: 'zazzle'}
    The function then searches for the 'role' entry and returns the corresponding item. If there is no such item, simply returns an empty string.
    Skips over quoted semi-colons and equals signs for example the string "foo=bar'&'role'='admin&baz=quz" produces
    {foo: "bar'&'role'='admin", baz=quz}
    """
    # (?<!') matches something that doesn't come after a '
    # (?<!')& matches & except if it comes after a '
    # (?<!')&(?!') matches & except if it is wrapped in quotes
    pairs = re.split(b'(?<!");(?!")', message)
    pairs = [re.split(b'(?<!")=(?!")', pair) for pair in pairs]
    profile = {pair[0]: pair[-1] for pair in pairs}
    return profile.get(b'admin', b'')


def create_server_client():
    key = secrets.token_bytes(32)
    class client:
        def __init__(self):
            self.prefix = b'comment1=cooking%20MCs;userdata='
            self.suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
            self.quote_chars = b'=;'
            self.engine = BlockCipherCTR('aes', key, 8)
        
        def __call__(self, message: bytes) -> bytes:
            for c in self.quote_chars:
                d = bytes([c])
                message = message.replace(d, b'"' + d + b'"')
            return self.engine.encrypt(self.prefix + message + self.suffix)

    class server:
        def __init__(self):
            self.engine = BlockCipherCTR('aes', key, 8)
        def __call__(self, ciphertext: bytes) -> bytes:
            message = self.engine.decrypt(ciphertext)
            return parse_dict(message)
    
    return server(), client()
