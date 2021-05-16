from .Challenge import Challenge
from cryptolib.utils.conversion import hex_string_to_b64

class Challenge01(Challenge):
    """
    Title:
    Convert hex to base64

    Description:
    The string:
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    Should produce:
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    So go ahead and make that happen. You'll need to use this code for the rest of the exercises. 
    """

    input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    solution = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    
    def solve(self) -> str:
        return hex_string_to_b64(self.input_str)

class Challenge02(Challenge):
    """
    Title:
    Fixed XOR

    Description:
    Write a function that takes two equal-length buffers and produces their XOR combination.
    If your function works properly, then when you feed it the string:
    1c0111001f010100061a024b53535009181c
    ... after hex decoding, and when XOR'd against:
    686974207468652062756c6c277320657965
    ... should produce:
    746865206b696420646f6e277420706c6179
    """
    

if __name__ == '__main__':
    unittest.main()