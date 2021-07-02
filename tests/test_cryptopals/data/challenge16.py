from typing import Tuple
from cryptolib.pipes import CBCDecrypt, StripPKCS7
from cryptolib.oracles import Oracle, SequentialOracle, AdditionalPlaintextWithQuotingOracle

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


def create_server_client() -> Tuple[SequentialOracle, SequentialOracle]:
    key = secrets.token_bytes(32)
    client = AdditionalPlaintextWithQuotingOracle(
        secret_prefix=rb"comment1=cooking%20MCs;userdata=",
        secret_suffix=rb";comment2=%20like%20a%20pound%20of%20bacon",
        quote_chars=b";=",
        mode='cbc',
        key=key,
        fix_iv=True
    )
    server = SequentialOracle([
        CBCDecrypt('aes', key),
        StripPKCS7(),
        Oracle(parse_dict),
    ])
    client.iv = secrets.token_bytes(16)
    server.iv = client.iv
    return server, client
