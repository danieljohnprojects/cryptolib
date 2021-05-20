from .Challenge import Challenge

from cryptolib.blockciphers import CBCMode

from cryptolib.oracles import ECB_CBC_oracle

from cryptolib.utils.conversion import b64_string_to_hex
from cryptolib.utils.padding import pkcs7

from .data import challenge10

class Challenge09(Challenge):
    """
     A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

    One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

    So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance, 

    "YELLOW SUBMARINE"

    ... padded to 20 bytes would be:

    "YELLOW SUBMARINE\\x04\\x04\\x04\\x04"
    """
    test_in = bytes(b"YELLOW SUBMARINE")
    solution = bytes(b"YELLOW SUBMARINE\x04\x04\x04\x04")
    def __init__(self):
        self.name = "Challenge09"
    def solve(self) -> bytes:
        return pkcs7(self.test_in, 20)

class Challenge10(Challenge):
    """
     CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

    In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

    The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

    Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

    The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\\x00\\x00\\x00 &c) 
    """
    ciphertext = challenge10.ciphertext
    solution = challenge10.solution
    def __init__(self):
        self.name = "Challenge10"

    def solve(self):
        ciphertext = bytes.fromhex(b64_string_to_hex(self.ciphertext))
        cipher = CBCMode('AES', bytes(b'YELLOW SUBMARINE'), IV = bytes([0] * 16))
        return cipher.decrypt(ciphertext)
    
class Challenge11(Challenge):
    """
     Now that you have ECB and CBC working:

    Write a function to generate a random AES key; that's just 16 random bytes.

    Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

    The function should look like:

    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]

    Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

    Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

    Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening. 
    """
    oracle = ECB_CBC_oracle()
    def __init__(self):
        self.name = "Challenge11"

    def solve(self):
        """
        The message we send must have two identical blocks encrypted. Since we always prepend at least 5 bytes we need to fill the first block with  at most 11 bytes, then add two more blocks that are the same. So the message needs to be at least 11 + 2 * 16 = 43 bytes long.
        """
        message = bytes(b'a' * 43)
        ciphertext = self.oracle.divine(message)
        # Chop the ciphertext into blocks
        B = 16
        blocks = [ciphertext[i*B:(i+1)*B] for i in range(len(ciphertext) // B)]
        # If one of the blocks repeat we have ECB mode
        if len(blocks) != len(set(blocks)):
            return 'ECB'
        # Otherwise it must be CBC
        else:
            return 'CBC'
            
    def postsolve(self):
        self.solution = self.oracle._last_choice

def test_all():
    challenges = [
        Challenge09(),
        Challenge10(),
        Challenge11(),
        ]
    for challenge in challenges:
        challenge.test_challenge()