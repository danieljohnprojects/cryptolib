import secrets
from math import ceil

from cryptolib.prfs import BytesFromNumbers
from cryptolib.utils.byteops import block_xor

secret_key = secrets.token_bytes(2)

def oracle(message: bytes) -> bytes:
    byteGenerator = BytesFromNumbers('mt19937', b'\x00\x00' + secret_key, 'little')
    plaintext = secrets.token_bytes(secrets.choice(range(20))) + message

    required_blocks = ceil(len(plaintext) / byteGenerator.output_length)
    keystream = b''.join([byteGenerator.rand() for _ in range(required_blocks)])
    keystream = keystream[:len(plaintext)]
    return block_xor(keystream, plaintext)