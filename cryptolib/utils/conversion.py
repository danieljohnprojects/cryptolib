"""
Functions for converting data from one format to another.
"""

import base64

__all__ = ['hex_string_to_b64', 'b64_string_to_hex']

def hex_string_to_b64(hexstr: str) -> str:
    """
    Takes in a string of hexadecimal digits and converts it to the corresponding base 64 representation of the same number.
    """
    b = bytes.fromhex(hexstr)
    return str(base64.b64encode(b))

def b64_string_to_hex(b64str: str) -> str:
    """
    Takes in a string of base 64 digits and converts it to the corresponding hexadecimal representation of the same number.
    """
    b = base64.b64decode(b64str)
    return b.hex()