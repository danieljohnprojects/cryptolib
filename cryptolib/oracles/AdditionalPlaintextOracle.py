from typing import Optional

from .Oracle import Oracle
from ..pipes import BCEncryptPipe, PadPKCS7Pipe

class AdditionalPlaintextOracle(Oracle):
    """
    Takes in a message, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a random but fixed key in ECB mode.
    """
    def __init__(self, 
            secret_prefix: bytes=b'', 
            secret_suffix: bytes=b'',
            algorithm: str = "AES",):
        self.pipeline = [
            lambda message: secret_prefix + message + secret_suffix,
            PadPKCS7Pipe(),
            BCEncryptPipe('ecb', algorithm)
        ]