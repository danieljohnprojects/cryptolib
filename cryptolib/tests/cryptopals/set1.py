from .Challenge import Challenge

from cryptolib.blockciphers import ECBMode

from cryptolib.cracks.substitution import decrypt_single_byte_xor, decrypt_repeating_key_xor

from cryptolib.utils.byteops import cyclical_xor
from cryptolib.utils.conversion import hex_string_to_b64, b64_string_to_hex
from cryptolib.utils.plain_scoring import score

from .data import challenge04, challenge06, challenge07, challenge08

import unittest

class Challenge01(Challenge):
    """
    Title:
    Convert hex to base64

    Description:
    The string:
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    Should produce:
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    So go ahead and make that happen. You'll need to use this code for the rest of the exercises. 
    """

    input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    solution = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    
    def __init__(self):
        self.name = "Challenge01"

    def solve(self) -> str:
        return hex_string_to_b64(self.input_str)

class Challenge02(Challenge):
    """
    Title:
    Fixed XOR

    Description:
    Write a function that takes two equal-length buffers and produces their XOR combination.
    If your function works properly, then when you feed it the string:
    1c0111001f010100061a024b53535009181c
    ... after hex decoding, and when XOR'd against:
    686974207468652062756c6c277320657965
    ... should produce:
    746865206b696420646f6e277420706c6179
    """
    message = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    key = bytes.fromhex('686974207468652062756c6c277320657965')
    solution = bytes.fromhex('746865206b696420646f6e277420706c6179')
    
    def __init__(self):
        self.name = "Challenge02"

    def solve(self) -> bytes:
        return cyclical_xor(self.key, self.message)
    
class Challenge03(Challenge):
    """
    Title:
    Single-byte XOR cipher

    Description:
    The hex encoded string: 
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
     ... has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score. 
    """
    cipher = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    solution = bytes(b"Cooking MC's like a pound of bacon")
    
    def __init__(self):
        self.name = "Challenge03"

    def solve(self) -> bytes:
        return decrypt_single_byte_xor(self.cipher)[0]

class Challenge04(Challenge):
    """
    Title:
    Detect single-character XOR

    Description:
     One of the 60-character strings in this file has been encrypted by single-character XOR.

    Find it.

    (Your code from #3 should help.) 
    """
    ctexts = challenge04.ciphertexts
    solution = bytes(b'Now that the party is jumping\n')
    
    def __init__(self):
        self.name = "Challenge04"
    
    def solve(self) -> bytes:
        plain = bytes(b'')
        best_score = 1e10
        for cipher in self.ctexts:
            this_plain, _ = decrypt_single_byte_xor(bytes.fromhex(cipher))
            if (this_score := score(this_plain)) < best_score:
                plain = this_plain
                best_score = this_score
        return plain
    
class Challenge05(Challenge):
    """
    Title:
    Implement repeating-key XOR

    Description:
    Here is the opening stanza of an important work of the English language: 
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
    Encrypt it, under the key "ICE", using repeating-key XOR.

    In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

    It should come out to:

    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

    Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise,we aren't wasting your time with this. 
    """
    plaintext = bytes(
        b"Burning 'em, if you ain't quick and nimble\n"
        b"I go crazy when I hear a cymbal"
        )
    key = bytes(b'ICE')
    solution = bytes.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    
    def __init__(self):
        self.name = "Challenge05"


    def solve(self) -> bytes:
        return cyclical_xor(self.key, self.plaintext)

class Challenge06(Challenge):
    """
    Title:

    Description:
    There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

    Decrypt it.

    Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

    This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important. 
    """
    ciphertext = challenge06.cipher
    solution = challenge06.solution
    
    def __init__(self):
        self.name = "Challenge06"

    def solve(self) -> bytes:
        c = bytes.fromhex(b64_string_to_hex(self.ciphertext))
        return decrypt_repeating_key_xor(c, range(2, 40))[0]

class Challenge07(Challenge):
    """
    Title:
    AES in ECB mode

    Description:
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW  SUBMARINE" because it's exactly 16 bytes long, and now you do too).

    Decrypt it. You know the key, after all.

    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 
    """
    ciphertext = bytes.fromhex(b64_string_to_hex(challenge07.cipher))
    key = bytes(b'YELLOW SUBMARINE')
    solution = bytes(challenge07.solution)
    
    def __init__(self):
        self.name = "Challenge07"

    def solve(self) -> bytes:
        blockcipher = ECBMode('AES', self.key)
        return blockcipher.decrypt(self.ciphertext)

class Challenge08(Challenge):
    """
    Title:
    Detect AES in ECB mode

    Description:
    In this file are a bunch of hex-encoded ciphertexts.

    One of them has been encrypted with ECB.

    Detect it.

    Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    """
    ciphertexts = challenge08.ciphertexts

    solution = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'

    def __init__(self):
        self.name = "Challenge08"

    def solve(self):
        B = 16
        ecb_enc = None
        for ctext in self.ciphertexts:
            N = len(ctext) // B
            blocks = [ctext[B*i:B*(i+1)] for i in range(N)]
            if len(blocks) != len(set(blocks)):
                ecb_enc = ctext
        return ecb_enc
    

def test_all():
    challenges = [
        Challenge01(),
        Challenge02(),
        Challenge03(),
        Challenge04(),
        Challenge05(),
        Challenge06(),
        Challenge07(),
        Challenge08(),
        ]
    for challenge in challenges:
        challenge.test_challenge()