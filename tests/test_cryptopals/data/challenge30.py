import secrets
from cryptolib.hashes.MD4 import md4digest
from cryptolib.hashes.MAC import prependMAC

def construct_signer_verifier(key_length: int):
    key = secrets.token_bytes(key_length)
    sign = prependMAC(md4digest, key)
    def verify(message: bytes, mac: bytes) -> bool:
        return sign(message) == mac
    return sign, verify