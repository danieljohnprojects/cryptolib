from abc import ABC, abstractclassmethod
from cryptolib.blockciphers.engines.AES import AES
from .engines import *
from cryptolib.utils import padding

class Mode(ABC):
    """
    An abstract block cipher mode.

    A block cipher mode wraps a block cipher engine and allows for easier encryption of long messages. A concrete realisation of this class may support the use of an IV or nonce and may automatically add padding as needed.
    """

    algorithms = {'AES': AES}
    padding_methods = {'NoPadding': padding.no_padding}

    @abstractclassmethod
    def __init__(self, 
        algorithm: str,
        key: bytes, 
        IV: bytes = bytes(b''), 
        nonce: bytes = bytes(b''),
        padding: str = 'NoPadding'):
        pass

    @abstractclassmethod
    def encrypt(self, message: bytes, IV: bytes = None):
        pass

    @abstractclassmethod
    def decrypt(self, ciphertext: bytes, IV: bytes = None):
        pass