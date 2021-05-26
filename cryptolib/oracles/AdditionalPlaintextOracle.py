import secrets

from .BCOracle import BCOracle

class AdditionalPlaintextOracle(BCOracle):
    """
    Takes in a message, prepends a secret prefix, appends a secret suffix, and encrypts it with a random but fixed key.
    """
    def __init__(self, 
            secret_prefix: bytes=b'', 
            secret_suffix: bytes=b'',
            mode: str = "ECB",
            algorithm: str = "AES",
            padding: str = "pkcs7",
            key: bytes = None,
            IV: bytes = None):
        super().__init__(mode, algorithm, padding, key=key, IV=IV)
        self.__secret_prefix = secret_prefix
        self.__secret_suffix = secret_suffix

    def _preprocess(self, message: bytes) -> bytes:
        return self.__secret_prefix + message + self.__secret_suffix