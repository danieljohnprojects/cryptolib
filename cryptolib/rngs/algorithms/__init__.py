from .LCG import LCG
from .MT19937 import MT19937

RNG_generators = {
    "mt19937" : MT19937,
    "lcg" : LCG
}