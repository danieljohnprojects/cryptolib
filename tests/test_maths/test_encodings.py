import pytest
from cryptolib.maths.encoding import encode_as_combination, decode_combination, numberToBase

def test_encode_as_combination():
    # x out of bounds
    with pytest.raises(ValueError) as error:
        n, k = 5, 2
        assert(encode_as_combination(-1, n, k))
        assert(encode_as_combination(10, n, k))

    # k out of bounds
    with pytest.raises(ValueError) as error:
        n, x = 5, 2
        assert(encode_as_combination(x, n, -1))
        assert(encode_as_combination(x, n, 6))

    assert encode_as_combination(0, 5, 2) == '00011'
    assert encode_as_combination(9, 5, 2) == '11000'
    encodings = [encode_as_combination(x, 5, 2) for x in range(10)]
    