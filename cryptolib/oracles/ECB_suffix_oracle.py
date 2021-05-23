import secrets

from ..blockciphers import ECBMode
from ..utils.conversion import b64_string_to_hex
from .BCOracle import BCOracle

class ECB_suffix_oracle(BCOracle):
    """
    Takes in a message, appends a secret suffix to it and encrypts it with a random but fixed key.
    """

    def __init__(self, secret_suffix_b64: str):
        self.__secret_suffix = bytes.fromhex(b64_string_to_hex( secret_suffix_b64 ))
        self.__ecb = ECBMode('AES', secrets.token_bytes(16), padding='pkcs7')

    def divine(self, message: bytes) -> bytes:
        return self.__ecb.encrypt(message + self.__secret_suffix)