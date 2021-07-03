from .SequentialOracle import SequentialOracle

from ..pipes import CBCDecrypt, ECBDecrypt
from ..utils.padding import is_valid_pkcs7


class PaddingOracle(SequentialOracle):
    """
    Takes in an encrypted message, decrypts it, checks the padding on the decrypted message, and returns either b'good' or b'bad' depending on whether the padding was correct.

    The first block of ciphertext should be the IV, the rest should be the actual ciphertext.
    """

    def __init__(self,
                 mode: str,
                 algorithm: str,
                 key: bytes,
                 **kwargs):
        pipeline = []
        if mode == 'ecb':
            pipeline.append(ECBDecrypt(algorithm, key))
        elif mode == 'cbc':
            pipeline.append(CBCDecrypt(algorithm, key))
        else:
            raise ValueError(f"Mode not supported. Got {mode}.")
        
        pipeline.append(
            lambda message: b'good' if is_valid_pkcs7(message) else b'bad'
        )

        super().__init__(pipeline, **kwargs)
