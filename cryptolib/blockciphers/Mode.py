from abc import ABC, abstractclassmethod
from cryptolib.blockciphers.engines.AES import AES
from .engines import *
from cryptolib.utils.padding import Padder

class Mode(ABC):
    """
    An abstract block cipher mode.

    A block cipher mode wraps a block cipher engine and allows for easier encryption of long messages. A concrete realisation of this class may support the use of an IV or nonce and may automatically add padding as needed.
    """

    _algorithms = {'AES': AES}

    @abstractclassmethod
    def __init__(self, 
        algorithm: str,
        key: bytes, 
        padding: str = 'NoPadding'):
        self._engine = (self._algorithms[algorithm])(key)
        self.B = self._engine.block_size
        self.padder = Padder(padding, self.B)

    @abstractclassmethod
    def encrypt(self, message: bytes, IV: bytes = None):
        pass

    @abstractclassmethod
    def decrypt(self, ciphertext: bytes, IV: bytes = None):
        pass