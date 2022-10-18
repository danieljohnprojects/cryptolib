import secrets
import time
from cryptolib.hashes.SHA1 import sha1digest
from cryptolib.hashes.MAC import HMAC

sleep_time = 0.0003
key_len = 16
mac_len = 20
# sign, verify = HMAC(sha1digest, secrets.token_bytes(key_len), sleep_time=sleep_time)
_, verify = HMAC(sha1digest, secrets.token_bytes(key_len), sleep_time=sleep_time)
message = b"You don't know the key, how could you forge a signature??"

def time_to_verify(sig: bytes) -> float:
    min_time = float('inf')
    for _ in range(10):
        t = time.time()
        verify(message, sig)
        t = time.time() - t
        min_time = t if t < min_time else min_time
    return min_time