import secrets

from typing import Optional

from .Oracle import Oracle

from ..blockciphers import ECBMode, CBCMode
from ..utils.byteops import bytes_to_blocks
from ..utils.padding import Padder

class BCOracle(Oracle):
    """A block cipher en/decryption oracle. 
    
    An oracle that encrypts a message using a specified algorithm, block cipher mode, key, padding strategy, and IV.

    Can be extended to include pre/post-processing of messages.

    Arguments:
        mode 
            The block cipher mode to use. Must be one of:
            -ECB
            -CBC
            inputted as a string (case insensitive).
        algorithm  
            The algorithm of the underlying block cipher. Must be one of:
            -AES
            inputted as a string (case insensitive).
        padding 
            The padding strategy to use. Must be one of:
            -nopadding
            -pkcs7
            inputted as a string (case insensitive).
        key
            The encryption key used to key the algorithm. If not provided a random one is generated.
        IV
            The "Initialisation Vector" used to initialise the block cipher mode. If not provided a random one is generated except if the ECB mode is chosen, in which case none is needed.
        decrypt
            A boolean flag to set the oracle to decrypt rather than encrypt. If True then decrypt, if False then encrypt. Defaults to False.
    
    Methods:
        divine
            The main method of the oracle. In this case the message is provided as a string of bytes. The message is then preprocessed according to the behaviour defined in the _preprocess function. The processed string is then padded, split into blocks and passed to the de/encryption engine. The de/encrypted message is then postprocessed according to the _postprocess function and then returned to the user.
    
    The _preprocess, _encrypt, and _postprocess functions can be extended to allow for the desired behaviour. These functions are prefixed with an underscore to indicate they should not be used trying to attacking the oracle. It is expected that these functions be overwritten to display different styles of attacks. 
    
    When attacking an oracle only input and output from the divine method should be used (this could include side channel information such as error handling). 
    """
    def __init__(self, 
            mode: str, 
            algorithm: str, 
            padding: str,
            key: Optional[bytes] = None, 
            IV: Optional[bytes] = None,
            decrypt: bool = False):

        # First initialise the encryption engine
        if not key:
            key = secrets.token_bytes(16)
        if mode.lower() == "ecb":
            if IV:
                raise ValueError("ECB mode takes no IV.")
            self._cipher = ECBMode(algorithm, key)
        else:
            if not IV:
                IV = secrets.token_bytes(16)
            if mode.lower() == "cbc":
                self._cipher = CBCMode(algorithm, key, IV)
            else:
                raise ValueError(f"{mode} is not a recognised mode.")
        
        # Then initialise the Padder
        self._padder = Padder(padding, self._cipher.block_size)

        # Decide whether or not to encrypt or decrypt.
        self._crypt = self._decrypt if decrypt else self._encrypt

    def _preprocess(self, message: bytes) -> bytes:
        """
        Returns the input. Can be extended to change the behaviour.

        This function is applied before the encryption step.
        """
        return message

    def _encrypt(self, message: bytes) -> bytes:
        """
        Encrypts the message with the internal block cipher engine. Behaviour can be modified (for example to change the IV).
        """
        padded_message = self._padder.pad(message)
        message_blocks = bytes_to_blocks(padded_message, self._cipher.block_size)
        cipher_blocks = self._cipher.encrypt(message_blocks)
        return b''.join(cipher_blocks)

    def _decrypt(self, message: bytes) -> bytes:
        """
        Decrypts the message with the internal block cipher engine. Behaviour can be modified (for example to change the IV).
        """
        message_blocks = bytes_to_blocks(message, self._cipher.block_size)
        plain_blocks = self._cipher.decrypt(message_blocks)
        padded_plain = b''.join(plain_blocks)
        return self._padder.strip(padded_plain)

    def _postprocess(self, message: bytes) -> bytes:
        """
        Returns the input. Can be extended to change the behaviour.

        This function is applied after the encryption step.
        """
        return message

    def divine(self, message: bytes) -> bytes:
        preprocessed = self._preprocess(message)
        crypted = self._crypt(preprocessed)
        return self._postprocess(crypted)