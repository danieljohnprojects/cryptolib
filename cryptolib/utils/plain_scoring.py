"""
Functions for scoring plaintext decryptions.
"""
from cgitb import small
from functools import reduce
from pydoc import plain
from string import printable
import re

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
    },
    '1337': {
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
        'w': 1, # A bit lower than normal
        'x': 4, # Much lower than normal
        'y': 4,
        'z': 4, # Much lower than normal
        
        '4': 1, # Same as 'a'
        '@': 1, # Same as 'a'
        '8': 3, # Same as 'b'
        '3': 1, # Same as 'e'
        '0': 1, # Same as 'o'
        '7': 1, # Same as 't'
        '1': 1, # Same as 'i' and 'l'
        '!': 1, # Same as 'i' and 'l'
        '&': 3, # Pops up sometimes
        '~': 8, # Pops up sometimes
        '_': 1, # Same as ' ' in scrabble scoring
    }
}

class Scorer:
    """
    A class that handles scoring of plaintext.
    """
    def __init__(self, 
                character_scores: dict = scoring_systems['inv_frequency'], 
                special_score: float = 20, 
                OOV_score: float = 200):
        self.character_scores = character_scores
        for c in printable:
            self.character_scores[c] = self.character_scores.get(c, special_score)
        self.OOV_score = OOV_score

    def score(self, plaintext: bytes):
        score = 0
        for b in plaintext:
            c = chr(b).lower()
            score += self.character_scores.get(c, self.OOV_score)
        return score

class ScrabbleScorer(Scorer):
    def __init__(self):
        super().__init__(scoring_systems['scrabble'])

class LeetScorer(Scorer):
    def __init__(self):
        super().__init__(scoring_systems['1337'], special_score=10)

class CTFFlagScorer(LeetScorer):
    CTF_pattern = re.compile(r"^[a-zA-Z]{3,20}\{[^\s\}]{1,50}\}$")
    relaxed_CTF_pattern = re.compile(r"[a-zA-Z]{3,20}\{[^\s\}]{1,50}\}")

    def score(self, plaintext: bytes):
        """
        Scores plaintext, penalising text that does not follow usual CTF format.

        We define CTF format as a string matching the regular expression: 
            ^[a-zA-Z]{3,20}\{[^\s\}]{1,50}\}$

        Penalisations follows these heuristics:
          - Plaintext matching the CTF format will incur no penalty.
          - Plaintext that appears to be a CTF flag with some extra stuff either appended or prepended will incur a small penalty.
          - Plaintext that includes some characters in the that are not printable ascii will incur a small penalty for each non ascii character.
          - Otherwise the plaintext will incur a large penalty.
        """
        score = 0
        # max_prefix_len = 12 # Arbitrarily choose a maximum length for the prefix
        small_penalty = 200
        large_penalty = 5000

        # The last six characters in string.printable are whitespace characters
        goodchars = [chr(c) in printable[:-6] for c in plaintext]

        if (num_bad_chars := goodchars.count(False)):
            # There are some characters here that don't belong.
            score += small_penalty * num_bad_chars
            # Remove bad characters
            plaintext = reduce(str.__add__, [chr(c) if isGood else '' for c, isGood in zip(plaintext, goodchars)])
        else:
            plaintext = str(plaintext, 'ascii')

        if self.CTF_pattern.search(plaintext):
            pass
        elif self.relaxed_CTF_pattern.search(plaintext):
            score += small_penalty
        else:
            score += large_penalty

        score += super().score(bytes(plaintext, 'ascii'))

        return score
