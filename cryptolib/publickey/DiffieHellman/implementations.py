import random
import secrets
from math import ceil
from .DiffieHellman import DH_Factory
from ...hashes.SHA1 import sha1digest

def micro_DH():
    """
    Simple implementation of Diffie Hellman with test parameters just to check that everything works.
    """
    rng = random.Random(12345)
    p = 37
    g = 5
    return DH_Factory(p, g,
        number_generator=lambda : rng.randrange(2, p),
        KDF = lambda k: k.to_bytes(2, 'big')
    )

def modp2048():
    """
    Implementation using NIST parameters set out in:
        https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
        https://www.rfc-editor.org/rfc/rfc3526
    Security is estimated to be approximately 112 bits.
    Note that this implementation does not conform to the standards set out in the above references. For example we do not go to the trouble of using an approved key derivation method. Instead we just hash it with SHA-1 (this is probably very bad and you should never use this in practice but this is just to demonstrate the Diffie-Hellman part).
    """
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    p_len = p.bit_length()//8
    
    g = 2
    
    return DH_Factory(p, g,
        number_generator=lambda : secrets.randbelow(p), 
        KDF = lambda k: sha1digest(k.to_bytes(p_len, 'big'))
    )
    
def export_grade():
    """
    This parameter set was shown to be exploitable in the famous Logjam attack.
    See https://weakdh.org/ for more details or the following technical paper:
        https://dl.acm.org/doi/pdf/10.1145/2810103.2813707
    """
    p = 0x9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e374171fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa87103
    
    p_len = ceil(p.bit_length()/8)
    
    g = 2
    return DH_Factory(p, g,
        number_generator=lambda : secrets.randbelow(p), 
        KDF = lambda k: sha1digest(k.to_bytes(p_len, 'big'))
    )