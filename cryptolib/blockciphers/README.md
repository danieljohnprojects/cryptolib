# Attacks on generic blockciphers

This module contains attacks that can be launched against a generic block cipher.
Attacks are separated into four categories:
   - Ciphertext only attacks - these are attacks attempt to determine some information about the plaintext or the underlying using only the provided ciphertext. In the case of a generic block cipher there is very little determine about the plaintext but we can sometimes determine the block cipher mode used in encrypting the ciphertext.
   - Plaintext ciphertext pairs - these attacks attempt to determine some information about the underlying block cipher using a given number of plaintexts and their corresponding cipher texts.
   - Chosen plaintext attacks - these attacks assume access to an oracle that, when provided with some (valid) plaintext, returns (some information relating to) the corresponding ciphertext.
   - Chosen ciphertext attacks - these attacks assume access to an oracle that, when provided with some (valid) ciphertext, returns (some information relating to) the corresponding plaintext.

In the case of a generic block cipher the most useful attacks will likely be the chosen plaintext and chosen ciphertext attacks.