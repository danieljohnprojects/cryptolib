from typing import Optional

from .SequentialOracle import SequentialOracle
from ..pipes import BCEncrypt, PadPKCS7


class AdditionalPlaintextOracle(SequentialOracle):
    """
    Takes in a message, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key in ECB mode.

    If no key is provided one is randomly generated.
    """

    def __init__(self,
                 secret_prefix: bytes = b'',
                 secret_suffix: bytes = b'',
                 mode: str = 'ecb',
                 algorithm: str = "AES",
                 key: Optional[bytes] = None,
                 iv: Optional[bytes] = None
                 ):
        self.pipeline = [
            lambda message: secret_prefix + message + secret_suffix,
            PadPKCS7(),
            BCEncrypt(
                mode=mode,
                algorithm=algorithm,
                key=key,
                iv=iv
            )
        ]
