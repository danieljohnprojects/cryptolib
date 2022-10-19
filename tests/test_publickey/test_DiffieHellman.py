import pytest
import random

from cryptolib.publickey.DiffieHellman.DiffieHellman import DH_Factory
from cryptolib.publickey.DiffieHellman.implementations import micro_DH, modp2048, export_grade

implementations = [
    micro_DH,
    modp2048,
    export_grade,
]

def test_implementations():
    incompatible_implementation = implementations[-1]
    for implementation in implementations:
        key_gen, shared_secret = implementation()
        
        for _ in range(50):
            privAlice, pubAlice = key_gen()
            privBob, pubBob = key_gen()
            assert shared_secret(privAlice, pubBob) == shared_secret(privBob, pubAlice)

        for _ in range(5):
            incompatible_key_gen, incompatible_shared_secret = incompatible_implementation()
            privAlice, pubAlice = key_gen()
            privCatherine, pubCatherine = incompatible_key_gen()
            with pytest.raises(RuntimeError):
                shared_secret(privAlice, pubCatherine)
            with pytest.raises(RuntimeError):
                incompatible_shared_secret(privCatherine, pubAlice)
        incompatible_implementation = implementation
