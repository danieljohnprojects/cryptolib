from cryptolib.utils.byteops import block_xor
from .data import challenge25


def test_challenge25():
    """
     Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

    Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

    Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

    Recover the original plaintext. 
    """
    enc_disc = challenge25.EncryptedDisc()

    ciphertext = enc_disc.get_encrypted_data()
    enc_disc.edit(0, b'\x00'*len(ciphertext))
    keystream = enc_disc.get_encrypted_data()
    
    plaintext = block_xor(keystream, ciphertext)
    assert plaintext == challenge25.plaintext




