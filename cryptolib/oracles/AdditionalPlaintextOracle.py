import random

from typing import Optional

from .SequentialOracle import SequentialOracle
from ..pipes import ECBEncrypt, CBCEncrypt, AddIV
from ..utils.padding import pkcs7


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
                 key: Optional[bytes] = None,
                 iv_seed: int = None,
                 fix_iv: bool = False,
                 **kwargs):        
        pipeline = [lambda message: secret_prefix + message + secret_suffix]
    
        if mode.lower() == 'ecb':
            engine_pipe = ECBEncrypt(algorithm, key)
        elif mode.lower() == 'cbc':
            engine_pipe = CBCEncrypt(algorithm, key)
        else:
            raise ValueError(f"{mode} mode is not supported.")

        block_size = engine_pipe.state['block_size']
        pad_pipe = lambda message: pkcs7(message, block_size)

        pipeline.append(pad_pipe)
        
        if mode.lower() != 'ecb':
            if fix_iv:
                random.seed(iv_seed)
                iv = random.randbytes(block_size)
                iv_pipe = lambda message: iv + message
                pipeline.append(iv_pipe)
            else:
                pipeline.append(AddIV(block_size, iv_seed))
        
        pipeline.append(engine_pipe)

        super().__init__(pipeline, **kwargs)

