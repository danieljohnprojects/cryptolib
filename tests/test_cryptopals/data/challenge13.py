from cryptolib.blockciphers.oracles import ECBoracle

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
    enc, dec = ECBoracle('aes')

    def client(message):
        prefix = b'email='
        suffix = b'&UID=10&role=user'
        quote_chars = b'=&'
        for c in quote_chars:
            b = bytes([c])
            message = message.replace(b, b'"' + b + b'"')
        return enc(prefix + message + suffix)

    def server(ciphertext: bytes) -> bytes:
        message = dec(ciphertext)
        return parse_dict(message)

    return server, client
