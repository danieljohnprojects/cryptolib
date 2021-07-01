import textwrap

from abc import ABC, abstractclassmethod
from typing import Sequence

from .engines import AES


class Mode(ABC):
    """An abstract block cipher mode.

    A Mode object provides an interface for block cipher encryption via an engine. This allows for the implementation of different block cipher modes and the use of an IV or nonce.

    Attributes:
        B
            The block size of the underlying engine.

    Methods:
        encrypt
            Takes in a sequence of blocks that are encrypted in order.
        decrypt
            Takes in a sequence of blocks that are decrypted in order.
    """

    _algorithms = {'aes': AES}

    @abstractclassmethod
    def __init__(self,
                 algorithm: str,
                 key: bytes):
        """
        Instantiates an engine using the algorithm and key provided.

        Arguments:
            algorithm
                The algorithm to use for the underlying engine. Passed as a string (case insensitive).
            key
                The key to use when encrypting.
        """
        try:
            self._engine = (self._algorithms[algorithm.lower()])(key)
        except KeyError as KE:
            raise KeyError(textwrap.dedent(
                f"""Algorithm "{algorithm}" is not supported.
                Algorithm must be one of:
                - aes (there is only one for now!)"""
            ))
        self.block_size = self._engine.block_size

    @abstractclassmethod
    def encrypt(self,
                message_blocks: Sequence[bytes]) -> Sequence[bytes]:
        """
        Encrypts a sequence of blocks according to some algorithm.
        """
        pass

    @abstractclassmethod
    def decrypt(self,
                cipher_blocks: Sequence[bytes]) -> Sequence[bytes]:
        """
        Decrypts a sequence of blocks according to some algorithm.
        """
        pass
