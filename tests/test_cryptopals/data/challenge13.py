from typing import Tuple
from cryptolib.pipes import ECBDecrypt
from cryptolib.oracles import SequentialOracle, AdditionalPlaintextWithQuotingOracle
from cryptolib.utils.padding import strip_pkcs7

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


def create_server_client() -> Tuple[SequentialOracle, SequentialOracle]:
    key = secrets.token_bytes(32)
    client = AdditionalPlaintextWithQuotingOracle(
        secret_prefix=b'email=',
        secret_suffix=b'&UID=10&role=user',
        quote_chars=b'=&',
        mode="ecb",
        algorithm="aes",
        key=key)
    server = SequentialOracle([
        ECBDecrypt('aes', key),
        lambda message: strip_pkcs7(message, 16),
        parse_dict,
    ])
    
    return server, client
