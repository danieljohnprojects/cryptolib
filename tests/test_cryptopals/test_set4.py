from cryptolib.utils.byteops import block_xor
from .data import challenge25, challenge26


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

def test_challenge26():
    """
     There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

    Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token. 
    """
    server, client = challenge26.create_server_client()
    # We want our message to decrypt to
    target_message = b';admin=true'
    # To do so we will send the string
    send_message = b':admin<true'

    xor_mask = block_xor(send_message, target_message)

    ciphertext = client(send_message)
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    for i in range(len(ciphertext) - len(send_message)):
        message_mask = b'\x00'*i + xor_mask + b'\x00'*(len(ciphertext) - len(xor_mask) - i)
        message = block_xor(ciphertext, message_mask)
        if server(nonce + message) == b"true":
            break
    else:
        assert False

