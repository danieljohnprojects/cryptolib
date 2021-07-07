import pytest

import base64

from cryptolib.cracks.bc_oracles import decrypt_with_padding_oracle
from cryptolib.cracks.two_time_pad import decrypt_two_time_pad
from cryptolib.pipes import CTR
from cryptolib.utils.padding import strip_pkcs7
from .data import challenge17, challenge19, challenge20


def test_Challenge17():
    """
    This is the best-known attack on modern block-cipher cryptography.

    Combine your padding code and your CBC code to write two functions.

    The first function should select at random one of the following 10 strings:

    MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
    MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
    MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
    MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
    MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
    MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
    MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
    MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
    MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
    MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

    ... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

    The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
    What you're doing here.

    This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

    It turns out that it's possible to decrypt the ciphertexts provided by the first function.

    The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

    You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

    The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

    02h in isolation is not valid padding.

    02h 02h is valid padding, but is much less likely to occur randomly than 01h.

    03h 03h 03h is even less likely.

    So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

    It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
    """
    server, client = challenge17.create_server_client()
    for message in challenge17.plaintexts:
        cipher = client(message)
        decrypted = strip_pkcs7(decrypt_with_padding_oracle(cipher, server, 'cbc'), 16)
        assert decrypted == message

def test_Challenge18():
    """
    The string:
    L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
    ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

        key=YELLOW SUBMARINE
        nonce=0
        format=64 bit unsigned little endian nonce,
                64 bit little endian block count (byte count / 16)

    CTR mode is very simple.

    Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.

    For instance, for the first 16 bytes of a message with these parameters:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    ... for the next 16 bytes:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

    ... and then:

    keystream = AES("YELLOW SUBMARINE",
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

    CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

    Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

    Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things. 
    """
    message = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')

    key = b'YELLOW SUBMARINE'
    oracle =  CTR('aes', key)
    nonce = bytes(8)
    decrypted = oracle(nonce + message)

    assert decrypted == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

def test_Challenge19():
    """
    Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

    In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts: 

    (This should produce 40 short CTR-encrypted ciphertexts).

    Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

    Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that: 
    CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

    And since the keystream is the same for every ciphertext:

    CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
    say!")

    Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on. 
    """
    ciphertexts = challenge19.ciphertexts
    plaintexts, _ = decrypt_two_time_pad(ciphertexts)
    for pt, message in zip(plaintexts, challenge19.messages):
        assert pt[:10] == message[:10]

def test_Challenge20():
    """
    In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

    Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

    Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

    To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

    Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd. 
    """
    ciphertexts = challenge20.ciphertexts
    plaintexts, _ = decrypt_two_time_pad(ciphertexts)
    for pt, message in zip(plaintexts, challenge20.messages):
        assert pt[:10] == message[:10]