import secrets

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ...maths.math import xgcd


@dataclass
class RSAPublicKey:
    N: int
    e: int


RSADecryptor = Callable[[bytes], bytes]


def TextbookRSAOracle(n: int = 2048, N: Optional[int] = None, e: int = 3) -> Tuple[RSAPublicKey, RSADecryptor]:
    """Constructs an RSA key pair and returns a public key P, and a function that decrypts messages that have been encrypted with P.

    Encryption is handled in a separate function.

    These functions implement the "textbook" version of RSA, where no padding is added to messages.
    Needless to say this is extremely insecure and should never be used in a production environment.

    Args:
        n (int, optional): The size in bits of the public key modulus. Defaults to 2048.
        N (int, optional): The modulus to use. If none is provided a modulus is generated at random.
        e (int, optional): The exponent to use. In none is provided a default value is used. Defaults to 3.

    Returns:
        Tuple[RSAPublicKey, RSADecryptor]: A public key consisting of a modulus and an exponent, and a decryption oracle.
    """
    def decrypt(ciphertext: bytes) -> bytes:
        return b''
    return RSAPublicKey(0, 0), decrypt


def TextbookRSAEncrypt(pk: RSAPublicKey, message: bytes) -> bytes:
    """Encrypts a message using the provided public key.

    The message m is encoded as a big-endian integer then the ciphertext c = m^e % N is returned where (N,e) is the public key.

    If the message is too large to be encoded as an integer modulo N raises an OverflowError.

    Args:
        pk (RSAPublicKey): The public key used to encrypt.
        message (bytes): The message to be encrypted.

    Returns:
        bytes: The encrypted message.

    Raises:
        OverflowError: If message is too large to be encoded appropriately.
    """
    return b''
