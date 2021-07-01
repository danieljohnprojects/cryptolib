from typing import Optional

from .Oracle import Oracle
from ..pipes import BCEncryptPipe, PadPKCS7Pipe

class AdditionalPlaintextWithQuotingOracle(Oracle):
    """
    Takes in a message, quotes out specific characters, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key in ECB mode.

    If no key is provided one is randomly generated.
    """
    def __init__(self,
            secret_prefix: bytes=b'', 
            secret_suffix: bytes=b'',
            quote_chars: bytes=b'',
            algorithm: str = "AES",
            key: Optional[bytes] = None
            ):
        self.pipeline = []
        for char in quote_chars:
            b = bytes(char)
            self.pipeline.append(
                lambda message: message.replace(b, b'"' + b + b'"')
            )

        self.pipeline += [
            lambda message: secret_prefix + message + secret_suffix,
            PadPKCS7Pipe(),
            BCEncryptPipe('ecb', algorithm, key)
        ]