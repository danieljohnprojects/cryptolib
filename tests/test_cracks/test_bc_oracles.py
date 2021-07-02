import pytest
import random

from cryptolib.cracks.bc_oracles import (
    get_block_size,
    uses_ECB,
    get_additional_message_len,
    decode_suffix
)
from cryptolib.oracles import (
    Oracle,
    SequentialOracle, 
    AdditionalPlaintextOracle
)
from cryptolib.pipes import (
    ECBEncrypt,
    CBCEncrypt,
    PadPKCS7
)

random.seed(1)

def test_ecb_oracle():
    # Try with an easy one
    oracle = SequentialOracle([
        PadPKCS7(),
        ECBEncrypt('aes')
    ])
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (0,0)

def test_ecb_with_additional_plaintext():
    # Try with a trickier one
    secret_prefix = random.randbytes(random.choice(range(5,14)))
    secret_suffix = random.randbytes(random.choice(range(5,14)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secret_prefix,
        secret_suffix=secret_suffix,
        mode='ecb',
        algorithm='aes'
    )
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (len(secret_prefix), len(secret_suffix))
    assert decode_suffix(oracle, len(secret_suffix), prefix_len=len(secret_prefix)) == secret_suffix

def test_fixed_iv_cbc_with_plaintext():
    # We can still decrypt cbc mode so long as the IV is fixed.
    secret_prefix = random.randbytes(random.choice(range(5,14)))
    secret_suffix = random.randbytes(random.choice(range(5,14)))
    oracle = AdditionalPlaintextOracle(
        secret_prefix=secret_prefix,
        secret_suffix=secret_suffix,
        mode='cbc',
        algorithm='aes',
        fix_iv=True
    )
    oracle.iv = random.randbytes(16)
    assert get_block_size(oracle) == 16
    assert not uses_ECB(oracle)
    assert get_additional_message_len(oracle) == (len(secret_prefix), len(secret_suffix))
    assert decode_suffix(oracle, len(secret_suffix), prefix_len=len(secret_prefix)) == secret_suffix

def test_cbc_with_changing_iv():
    # get_additional_message_len and decode_suffix don't work if IV changes
    secret_prefix = random.randbytes(random.choice(range(5,14)))
    secret_suffix = random.randbytes(random.choice(range(5,14)))
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
    prefix = random.randbytes(random.choice(range(6,35)))
    suffix = random.randbytes(random.choice(range(6,35)))
    secret_prefix = random.randbytes(random.choice(range(5,14)))
    secret_suffix = random.randbytes(random.choice(range(5,14)))
    oracle = SequentialOracle([
        Oracle(lambda message: prefix + message + suffix),
        AdditionalPlaintextOracle(
            secret_prefix=secret_prefix,
            secret_suffix=secret_suffix,
            mode='ecb',
            algorithm='aes'
        )
    ])
    assert get_block_size(oracle) == 16
    assert uses_ECB(oracle)