"""
Functions for converting data from one format to another.
"""

import base64

__all__ = ['hex_string_to_b64', 'b64_string_to_hex']


def hex_string_to_b64(hexstr: str) -> str:
    """
    Takes in a string of hexadecimal digits and converts it to the corresponding string of base 64 digits representing the same bytes.

    Note that this is not the same as converting a hexadecimal number to a base 64 number. The number 0xabc is q8 in base 64. However this function will throw an error given this input since 0xabc does not represent a string of eight bit bytes.

    Example:
    hex_string_to_b64('abcd') = 'q80='
    """
    b = bytes.fromhex(hexstr)
    return str(base64.b64encode(b))[2:-1]


def b64_string_to_hex(b64str: str) -> str:
    """
    Takes in a string of base 64 digits and converts it to the corresponding hexadecimal representation of the same number.
    """
    b = base64.b64decode(b64str)
    return b.hex()
