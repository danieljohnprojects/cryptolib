from cryptolib.oracles.PaddingOracle import PaddingOracle
import pytest
import random

from cryptolib.cracks.bc_oracles import (
    get_block_size,
    uses_ECB,
    get_additional_message_len,
    decode_suffix,
    decrypt_with_padding_oracle
)
from cryptolib.oracles import (
    SequentialOracle,
    AdditionalPlaintextOracle
)
from cryptolib.pipes import (
    ECBEncrypt,
    CBCEncrypt,
    AddIV
)

from cryptolib.utils.padding import pkcs7

random.seed(1)


def test_ecb_oracle():
    # Try with an easy one
    oracle = SequentialOracle([
        lambda message: pkcs7(message, 16),
        ECBEncrypt('aes')
    ])
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (0, 0)


def test_ecb_with_additional_plaintext():
    # Try with a trickier one
    secret_prefix = random.randbytes(random.choice(range(5, 14)))
    secret_suffix = random.randbytes(random.choice(range(5, 14)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secret_prefix,
        secret_suffix=secret_suffix,
        mode='ecb',
        algorithm='aes'
    )
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (
        len(secret_prefix), len(secret_suffix))
    assert decode_suffix(oracle, len(secret_suffix),
                         prefix_len=len(secret_prefix)) == secret_suffix


def test_fixed_iv_cbc_with_plaintext():
    # We can still decrypt cbc mode so long as the IV is fixed.
    secret_prefix = random.randbytes(random.choice(range(5, 14)))
    secret_suffix = random.randbytes(random.choice(range(5, 14)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secret_prefix,
        secret_suffix=secret_suffix,
        mode='cbc',
        algorithm='aes',
        fix_iv=True
    )
    # Add in a pipe to strip off the iv from the start.
    oracle.append_pipe(lambda message: message[16:])

    assert get_block_size(oracle) == 16
    assert not uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (
        len(secret_prefix), len(secret_suffix))
    assert decode_suffix(oracle, len(secret_suffix),
                         prefix_len=len(secret_prefix)) == secret_suffix


def test_cbc_with_changing_iv():
    # get_additional_message_len and decode_suffix don't work if IV changes
    secret_prefix = random.randbytes(random.choice(range(5, 14)))
    secret_suffix = random.randbytes(random.choice(range(5, 14)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secret_prefix,
        secret_suffix=secret_suffix,
        mode='cbc',
        algorithm='aes'
    )
    assert get_block_size(oracle) == 16
    assert not uses_ECB(oracle)


def test_ecb_with_plaintext_added_postencryption():
    # get_additional_message_len and decode_suffix also don't work properly if stuff has been added post encryption.
    prefix = random.randbytes(random.choice(range(6, 35)))
    suffix = random.randbytes(random.choice(range(6, 35)))
    secret_prefix = random.randbytes(random.choice(range(5, 14)))
    secret_suffix = random.randbytes(random.choice(range(5, 14)))
    oracle = SequentialOracle([
        AdditionalPlaintextOracle(
            secret_prefix=secret_prefix,
            secret_suffix=secret_suffix,
            mode='ecb',
            algorithm='aes'
        ),
        lambda message: prefix + message + suffix
    ])
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)


def test_decrypt_with_padding_oracle():
    random.seed(1)
    key = random.randbytes(16)
    enc = SequentialOracle([
        lambda message: pkcs7(message, 16),
        AddIV(seed=1),
        CBCEncrypt('aes', key)
    ])
    check_pad = PaddingOracle('cbc', 'aes', key)

    secret_messages = [
        b'Hello there, General Kenobi..',
        b"You are shorter than I expected",
        b'0123456789abcdef',
        b'a'*48,
        b'0123456789abcde',
        b'',
        b'a',
        b'abc',
    ]
    secret_messages += [random.randbytes(random.randint(10, 200))
                        for _ in range(10)]

    for message in secret_messages:
        cipher = enc(message)
        assert decrypt_with_padding_oracle(
            cipher, check_pad, 'cbc') == pkcs7(message, 16)

    for message in secret_messages:
        cipher = enc(message + message)
        assert decrypt_with_padding_oracle(
            cipher, check_pad, 'cbc') == pkcs7(message + message, 16)
