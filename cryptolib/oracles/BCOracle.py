from secrets import token_bytes
from .Oracle import Oracle

from ..blockciphers import ECBMode, CBCMode

class BCOracle(Oracle):
    """
    Block cipher encryption oracle. Can be extended to include pre and post processing of messages.

    Mode must be set to one of:
    - CBC
    - ECB

    Algorithm must be one of:
    - AES

    If key is provided that key is used to key the oracle, otherwise a random key is generated.
    """
    def __init__(self, 
            mode: str, 
            algorithm: str, 
            padding: str,
            key: bytes = None, 
            IV: bytes = None):
        if not key:
            key = token_bytes(16)
        if mode.lower() == "cbc":
            if not IV:
                IV = token_bytes(16)
            self.__cipher = CBCMode(algorithm, key, IV, padding)
        elif mode.lower() == "ecb":
            if IV:
                raise ValueError("ECB mode takes no IV.")
            self.__cipher = ECBMode(algorithm, key, padding)
        else:
            raise ValueError(f"{mode} is not a recognised mode.")

    def __preprocess(self, message: bytes) -> bytes:
        """
        Returns the input. Can be extended to change the behaviour.

        This function is applied before the encryption step.
        """
        return message

    def __encrypt(self, message: bytes) -> bytes:
        """
        Encrypts the message with the internal cipher. Behaviour can be modified (for example to change the IV).
        """
        return self.__cipher.encrypt(message)

    def __postprocess(self, message: bytes) -> bytes:
        """
        Returns the input. Can be extended to change the behaviour.

        This function is applied after the encryption step.
        """
        return message

    def divine(self, message: bytes) -> bytes:
        preprocessed = self.__preprocess(message)
        encrypted = self.__encrypt(preprocessed)
        return self.__postprocess(encrypted)