from typing import Optional

from .BCOracle import BCOracle

class AdditionalPlaintextOracle(BCOracle):
    """
    Takes in a message, prepends a secret prefix, appends a secret suffix, and encrypts it with a random but fixed key in ECB mode.
    """
    def __init__(self, 
            secret_prefix: bytes=b'', 
            secret_suffix: bytes=b'',
            mode: str = "ECB",
            algorithm: str = "AES",
            padding: str = "pkcs7",
            key: Optional[bytes] = None,
            IV: Optional[bytes] = None):
        super().__init__(mode, algorithm, padding, key=key, IV=IV)
        self._secret_prefix = secret_prefix
        self._secret_suffix = secret_suffix

    def _preprocess(self, message: bytes) -> bytes:
        return self._secret_prefix + message + self._secret_suffix