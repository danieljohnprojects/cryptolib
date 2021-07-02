from cryptolib.pipes.GenIV import GenIV
from typing import Optional

from .Oracle import Oracle
from .SequentialOracle import SequentialOracle
from ..pipes import ECBEncrypt, CBCEncrypt, PadPKCS7, GenIV


class AdditionalPlaintextOracle(SequentialOracle):
    """
    Takes in a message, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key in the specified mode.

    If no key is provided one is randomly generated.

    If the specified mode uses IVs, a new one is generated for each message.
    """

    def __init__(self,
                 secret_prefix: bytes = b'',
                 secret_suffix: bytes = b'',
                 mode: str = 'ecb',
                 algorithm: str = "AES",
                 key: Optional[bytes] = None):
        if mode == 'ecb':
            pipeline = [
                Oracle(lambda message: secret_prefix + message + secret_suffix),
                PadPKCS7(),
                ECBEncrypt(algorithm, key)
            ]
        elif mode == 'cbc':
            engine = CBCEncrypt(algorithm, key)
            pipeline = [
                GenIV(engine.block_size),
                Oracle(lambda message: secret_prefix + message + secret_suffix),
                PadPKCS7(),
                engine
            ]
        else:
            raise ValueError(f"Mode {mode} is not supported.")

        super().__init__(pipeline)

