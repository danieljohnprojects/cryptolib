from cryptolib.blockciphers.chosen_plain.oracles import EncryptECB
from cryptolib.blockciphers.chosen_cipher.oracles import DecryptECB

import re
import secrets


def parse_dict(message: bytes) -> bytes:
    """
    Takes in a string of the form "foo=bar&baz=qux&zap=zazzle" and produces a dictionary of the form 
    {foo: 'bar', baz: 'qux', zap: 'zazzle'}
    The function then searches for the 'role' entry and returns the corresponding item. If there is no such item, simply returns an empty string.
    Skips over quoted ampersands and equals signs for example the string "foo=bar'&'role'='admin&baz=quz" produces
    {foo: "bar'&'role'='admin", baz=quz}
    """
    # (?<!') matches something that doesn't come after a '
    # (?<!')& matches & except if it comes after a '
    # (?<!')&(?!') matches & except if it is wrapped in quotes
    pairs = re.split(b'(?<!")&(?!")', message)
    pairs = [re.split(b'(?<!")=(?!")', pair) for pair in pairs]
    profile = {pair[0]: pair[1] for pair in pairs}
    return profile.get(b'role', b'')


def create_server_client():
    key = secrets.token_bytes(32)
    class client:
        def __init__(self):
            self.prefix = b'email='
            self.suffix = b'&UID=10&role=user'
            self.quote_chars = b'=&'
            self.engine = EncryptECB('aes', key)
        
        def __call__(self, message: bytes) -> bytes:
            for c in self.quote_chars:
                b = bytes([c])
                message = message.replace(b, b'"' + b + b'"')
            return self.engine(self.prefix + message + self.suffix)

    class server:
        def __init__(self):
            self.engine = DecryptECB('aes', key)
        def __call__(self, ciphertext: bytes) -> bytes:
            message = self.engine(ciphertext)
            return parse_dict(message)
    
    return server(), client()
