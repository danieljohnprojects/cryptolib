import secrets
import time
from cryptolib.hashes.SHA1 import sha1digest, sha1extend, sha1extend_message
from cryptolib.hashes.MD4 import md4digest, md4extend, md4extend_message
from cryptolib.hashes.MAC import prefixMAC, HMAC
from cryptolib.utils.byteops import block_xor, reconstruct_from_str
from .data import challenge25, challenge26, challenge27, challenge28, challenge30

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

def test_challenge27():
    """
    Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

    Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

    Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

    The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

    Use your code to encrypt a message that is at least 3 blocks long:

    AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

    Modify the message (you are now the attacker):

    C_1, C_2, C_3 -> C_1, 0, C_1

    Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

    As the attacker, recovering the plaintext from the error, extract the key:

    P'_1 XOR P'_3
    """
    server, client = challenge27.create_server_client()

    message = b"a"*32
    ciphertext = client(message)
    try:
        # Add full ciphertext on the end so that padding works out.
        server(ciphertext[:16] + b'\x00'*16 + ciphertext) 
    except ValueError as vErr:
        errorMessage = vErr.args[0]
    prefix_len = len("Message ")
    suffix_len = len(" contains non-ascii characters!")
    plain = reconstruct_from_str(errorMessage[prefix_len:-suffix_len])
    key = block_xor(plain[:16], plain[32:48])
    assert key == client._engine._key_schedule[:16]

def test_challenge28():
    """
    Find a SHA-1 implementation in the language you code in.
    Don't cheat. It won't work.
    Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).

    Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

    SHA1(key || message)

    Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
    """
    
    message = b'will this be authenticated?'
    sign, verify = prefixMAC(sha1digest, secrets.token_bytes(16))
    mac = sign(message)
    assert verify(message, mac)
    altered_message = block_xor(message, b'\x01'*len(message))
    assert not verify(altered_message, mac)

def test_challenge29():
    key_len = 16
    sign, verify = prefixMAC(sha1digest, secrets.token_bytes(key_len))
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = sign(message)
    suffix = b';admin=true'
    new_mac = sha1extend(mac, len(message) + key_len, suffix)
    new_message = sha1extend_message(key_len, message, suffix)
    assert verify(new_message, new_mac)

def test_challenge30():
    key_len = 16
    sign, verify = prefixMAC(md4digest, secrets.token_bytes(key_len))
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = sign(message)
    suffix = b';admin=true'
    new_mac = md4extend(mac, len(message) + key_len, suffix)
    new_message = md4extend_message(key_len, message, suffix)
    assert verify(new_message, new_mac)