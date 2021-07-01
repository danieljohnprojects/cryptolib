import pytest

from cryptolib.utils.byteops import bytes_to_blocks

def test_bytes_to_blocks():
    assert bytes_to_blocks(b'abcd', 2) == [b'ab', b'cd']

    test_lengths = range(100)
    test_vectors = map(lambda n: b'a'*n, test_lengths)
    for block_size in range(2, 32):
        expected_outputs = []
        for i in test_lengths:
            q = i // block_size
            r = i % block_size
            if r: #q and r:
                expected_outputs.append(q*[block_size*b'a'] + [r*b'a'])
            elif q:
                expected_outputs.append(q*[block_size*b'a'])
            else:
                expected_outputs.append([])
        actual_outputs = map(
            lambda message: bytes_to_blocks(message, block_size), 
            test_vectors)
        for act,exp in zip(actual_outputs, expected_outputs):
            assert act==exp
    message = b'a' * 20
    try:
        bytes_to_blocks(message, 1)
    except ValueError:
        assert True