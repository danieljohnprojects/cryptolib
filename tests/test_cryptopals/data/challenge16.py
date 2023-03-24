from cryptolib.blockciphers.oracles import CBCoracle_FixedIV

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
    profile = {pair[0]: pair[1] for pair in pairs}
    return profile.get(b'admin', b'')


def create_server_client():
    key = secrets.token_bytes(32)
    enc, dec = CBCoracle_FixedIV()

    def client(message):
        prefix = b'comment1=cooking%20MCs;userdata='
        suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
        quote_chars = b'=;'

        for c in quote_chars:
            b = bytes([c])
            message = message.replace(b, b'"' + b + b'"')
        return enc(prefix + message + suffix)

    def server(ciphertext: bytes) -> bytes:
        message = dec(ciphertext)
        return parse_dict(message)

    return server, client
