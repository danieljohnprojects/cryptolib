import pytest

from cryptolib.utils.byteops import transpose

def test_transpose():
    assert transpose([b'012', b'345']) == [b'03', b'14', b'25']
