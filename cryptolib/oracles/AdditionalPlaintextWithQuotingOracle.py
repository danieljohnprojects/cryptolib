from typing import Optional

from .SequentialOracle import SequentialOracle
from ..pipes import BCEncrypt, PadPKCS7


class AdditionalPlaintextWithQuotingOracle(SequentialOracle):
    """
    Takes in a message, quotes out specific characters, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key and iv in the specified mode (defaults to ECB).

    If no key (iv) is provided one is randomly generated (if not in ECB mode).
    """

    def __init__(self,
                 secret_prefix: bytes = b'',
                 secret_suffix: bytes = b'',
                 quote_chars: bytes = b'',
                 mode: str = 'ecb',
                 algorithm: str = "AES",
                 key: Optional[bytes] = None,
                 iv: Optional[bytes] = None
                 ):
        self.pipeline = []
        for char in quote_chars:
            b = bytes(char)
            self.pipeline.append(
                lambda message: message.replace(b, b'"' + b + b'"')
            )

        self.pipeline += [
            lambda message: secret_prefix + message + secret_suffix,
            PadPKCS7(),
            BCEncrypt(mode, algorithm, key, iv)
        ]
