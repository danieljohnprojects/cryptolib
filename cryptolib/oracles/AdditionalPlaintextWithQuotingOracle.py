from typing import Optional

from .SequentialOracle import Oracle, SequentialOracle
from ..pipes import ECBEncrypt, CBCEncrypt, PadPKCS7, GenIV


class AdditionalPlaintextWithQuotingOracle(SequentialOracle):
    """
    Takes in a message, quotes out specific characters, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key in the specified mode.

    If no key is provided one is randomly generated.

    If the specified mode uses IVs, a new one is generated for each message.
    """

    def __init__(self,
                 secret_prefix: bytes = b'',
                 secret_suffix: bytes = b'',
                 quote_chars: bytes = b'',
                 mode: str = 'ecb',
                 algorithm: str = "AES",
                 key: Optional[bytes] = None,
                 fix_iv: bool = False
                 ):
        pipeline = []
        for char in quote_chars:
            b = bytes(char)
            pipeline.append(
                Oracle(lambda message: message.replace(b, b'"' + b + b'"'))
            )

        if mode == 'ecb':
            pipeline += [
                Oracle(lambda message: secret_prefix + message + secret_suffix),
                PadPKCS7(),
                ECBEncrypt(algorithm, key)
            ]
        else:
            if mode == 'cbc':
                engine = CBCEncrypt(algorithm, key)
            else:
                raise ValueError(f"Mode {mode} is not supported.")

            if not fix_iv:
                pipeline += [GenIV(engine.block_size)]
            pipeline += [
                Oracle(lambda message: secret_prefix + message + secret_suffix),
                PadPKCS7(),
                engine
            ]
        super().__init__(pipeline)
