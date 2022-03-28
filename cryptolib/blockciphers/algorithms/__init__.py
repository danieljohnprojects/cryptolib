from .BCEngine import BCEngine
from .AES import AES

# Mapping from name of algorithm to a tuple consisting of:
#  - a function for generating the engine
#  - an integer representing the default block size
engine_generators = {
    'aes': (AES, 16)
}
