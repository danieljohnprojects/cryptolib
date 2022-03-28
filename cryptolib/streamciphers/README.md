# Attacks on generic streamciphers

This module contains attacks on stream ciphers.
We separate attacks on stream ciphers into two categories:
   - Many-time pad attacks - in these attacks we assume that we have access to several ciphertexts which we believe to have been encrypted with the same keystream. The goal of these attacks is to find information about the corresponding plaintexts. This is effectively a language modelling problem rather than a cryptanalytic problem so we include only fairly rudimentary techniques.
   - Keystream analysis - in these attacks we assume we have access to a partial keystream. From this we hope to find some information about the future bytes of the keystream, or the system from which it was generated.

Note that these categories essentially entail all four categories included in block cipher module.
A plaintext-ciphertext pair can be obtained in a chosen plaintext or chosen ciphertext attack, revealing a partial keystream for analysis.
