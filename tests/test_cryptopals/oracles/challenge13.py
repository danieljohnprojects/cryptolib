from typing import Tuple
from cryptolib.pipes import BCDecrypt, StripPKCS7
from cryptolib.oracles import SequentialOracle, AdditionalPlaintextWithQuotingOracle

import re
import secrets


class server(SequentialOracle):
    def __init__(self, key: bytes):
        self.pipeline = [
            BCDecrypt('ecb', 'aes', key),
            StripPKCS7(),
            self.parse_dict,
            lambda message: self.profile[b'role']
        ]

    def parse_dict(self, message: bytes):
        """
        Takes in a string of the form "foo=bar&baz=qux&zap=zazzle" and produces a dictionary of the form 
        {foo: 'bar', baz: 'qux', zap: 'zazzle'}
        which is stored in the oracle's state.
        Skips over quoted ampersands and equals signs for example the string "foo=bar'&'role'='admin&baz=quz" produces
        {foo: "bar'&'role'='admin", baz=quz}
        """
        # (?<!') matches something that doesn't come after a '
        # (?<!')& matches & except if it comes after a '
        # (?<!')&(?!') matches & except if it is wrapped in quotes
        pairs = re.split(b'(?<!")&(?!")', message)
        pairs = [re.split(b'(?<!")=(?!")', pair) for pair in pairs]
        self.profile = {pair[0]: pair[1] for pair in pairs}
        return message


def create_server_client() -> Tuple[SequentialOracle, SequentialOracle]:
    key = secrets.token_bytes(32)
    client = AdditionalPlaintextWithQuotingOracle(
        secret_prefix=b'email=',
        secret_suffix=b'&UID=10&role=user',
        quote_chars=b'=&',
        mode="ecb",
        algorithm="aes",
        key=key)
    return server(key), client
