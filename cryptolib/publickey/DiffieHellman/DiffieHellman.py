"""
"""
from typing import Callable, NewType

DH_Private_Key = NewType('DH_Private_Key', int)
DH_Public_Key = tuple[int, int, int]

def DH_Factory(
        p: int, 
        g: int, 
        number_generator: Callable[[], int], 
        KDF: Callable[[int], bytes]
    ) -> (Callable[[], tuple[DH_Private_Key, DH_Public_Key]], Callable[[DH_Private_Key, DH_Public_Key], bytes]):
    """
    Given a parameter set creates the following oracles:
        - A key generation oracles that generate a public and private key.
        - An oracle that takes in a private key, and someone else's public key and derives a shared secret.
    
    Args:
        p - The order of the group. This is normally prime.
        g - The base point of the group. This is normally a generator of the multiplicative group modulo p.
        number_generator - A function that produces numbers between 1 and p-1 to be used as private keys.
        KDF - A key derivation function that is applied to the shared secret after it is produced.
    Returns:
        A key generation oracle and a shared secret oracle.
    """
    def key_generation_oracle() -> (DH_Private_Key, DH_Public_Key):
        private = DH_Private_Key(number_generator())
        pub = (p, g, pow(g, private, p))
        return private, pub
    
    def key_agreement_oracle(private: DH_Private_Key, pub: DH_Public_Key) -> bytes:
        p1, g1, pub = pub
        if p1 != p:
            raise RuntimeError(f"Incompatible public modulus! My modulus is {p}, I was asked to form a shared secret with a modulus of {p1}.")
        if g1 != g:
            raise RuntimeError(f"Incompatible public base point! My base point is {g}, I was asked to form a shared secret with a base point of {g1}.")
        shared_secret = pow(pub, private, p)
        return KDF(shared_secret)
    
    return key_generation_oracle, key_agreement_oracle