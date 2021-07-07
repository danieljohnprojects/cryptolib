"""
Functions for scoring plaintext decryptions.
"""
from string import printable
from typing import Optional

scoring_systems = {
    'scrabble': {
        'a': 1,
        'b': 3,
        'c': 3,
        'd': 2,
        'e': 1,
        'f': 4,
        'g': 2,
        'h': 4,
        'i': 1,
        'j': 8,
        'k': 5,
        'l': 1,
        'm': 3,
        'n': 1,
        'o': 1,
        'p': 3,
        'q': 10,
        'r': 1,
        's': 1,
        't': 1,
        'u': 1,
        'v': 4,
        'w': 4,
        'x': 8,
        'y': 4,
        'z': 10,
        ' ': 1,
        'special': 20
    },
    'inv_frequency': {
        'a': 1/8.2,
        'b': 1/1.5,
        'c': 1/2.8,
        'd': 1/4.3,
        'e': 1/13,
        'f': 1/2.2,
        'g': 1/2,
        'h': 1/6.1,
        'i': 1/7,
        'j': 1/0.15,
        'k': 1/0.77,
        'l': 1/4,
        'm': 1/2.4,
        'n': 1/6.7,
        'o': 1/7.5,
        'p': 1/1.9,
        'q': 1/0.095,
        'r': 1/6,
        's': 1/6.3,
        't': 1/9.1,
        'u': 1/2.8,
        'v': 1/0.98,
        'w': 1/0.24,
        'x': 1/0.15,
        'y': 1/2,
        'z': 1/0.074,
        ' ': 1/20,
        'special': 1/0.05
    }
}


def score(plaintext: bytes,
          scorer: Optional[dict] = None,
          OOV_score: float = 200) -> float:
    """
    Computes a score of a plaintext based on the given scoring system.
    OOV_score is the out of vocabulary score, that is, the score given to non printable characters.
    Defaults to using scrabble scoring.
    """
    if not scorer:
        scorer = scoring_systems['scrabble']
    score = 0
    for b in plaintext:
        c = chr(b).lower()
        if c in scorer.keys():
            score += scorer[c]
        elif c in printable:
            score += scorer['special']
        else:
            score += OOV_score
    return score
