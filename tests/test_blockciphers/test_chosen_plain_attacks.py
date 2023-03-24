import pytest
import random
from Crypto.Cipher import AES

from cryptolib.blockciphers.attacks.chosen_plain import get_block_size, diagnose_mode, get_additional_message_len, decrypt_suffix
from cryptolib.blockciphers.oracles import ECBoracle, CBCoracle, CBCoracle_FixedIV
from cryptolib.utils.padding import pkcs7


def test_get_block_size():
    rng = random.Random(12345)
    oracle, _ = ECBoracle('aes', rng.randbytes(16))
    assert get_block_size(oracle) == 16

    with pytest.raises(ValueError):
        get_block_size(oracle, -1)
    with pytest.raises(ValueError):
        get_block_size(oracle, 15)

    def oracle(message: bytes) -> bytes:
        if b'a' in message:
            raise Exception()
        return pkcs7(message, 25)

    # Check that the allowable_bytes argument avoids the disallowed character.
    assert get_block_size(oracle, allowable_bytes=b'bcdefghijklmnop') == 25


def test_get_additional_message_len():
    rng = random.Random(12345)

    class additional_plaintext_oracle_ecb:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine, _ = ECBoracle('aes', key)

        def __call__(self, message: bytes) -> bytes:
            return self.engine(self.prefix + message + self.suffix)

    class additional_plaintext_oracle_cbc_fixed_iv:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine, _ = CBCoracle_FixedIV(key)

        def __call__(self, message: bytes) -> bytes:
            return self.engine(self.prefix + message + self.suffix)

    class additional_plaintext_oracle_cbc:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine, _ = CBCoracle('aes', key)

        def __call__(self, message: bytes) -> bytes:
            # Don't forget to remove the IV.
            return self.engine(self.prefix + message + self.suffix)[16:]

    oracle = additional_plaintext_oracle_ecb()

    prefix_len, suffix_len = get_additional_message_len(oracle, 16)
    assert suffix_len == len(oracle.suffix)
    assert prefix_len == len(oracle.prefix)

    oracle = additional_plaintext_oracle_cbc_fixed_iv()

    prefix_len, suffix_len = get_additional_message_len(oracle, 16)
    assert suffix_len == len(oracle.suffix)
    assert prefix_len == len(oracle.prefix)

    with pytest.raises(ValueError):
        get_additional_message_len(oracle, 16, b'a')
    with pytest.raises(ValueError):
        get_additional_message_len(oracle, 16, b'aa')

    oracle = additional_plaintext_oracle_cbc()
    with pytest.raises(RuntimeError):
        prefix_len, suffix_len = get_additional_message_len(oracle, 16)


def test_diagnose_mode():
    rng = random.Random(12345)
    key = rng.randbytes(16)
    modes = {
        'cbc': CBCoracle_FixedIV(key)[0],
        'ecb': ECBoracle('aes', key)[0],
    }
    for mode, oracle in modes.items():
        assert diagnose_mode(oracle, 16) == mode

    # Check that probabilistic approach to CBC checking is working.
    for _ in range(100):
        key = rng.randbytes(16)
        oracle, _ = CBCoracle_FixedIV(key)
        assert diagnose_mode(oracle, 16) == 'cbc'

    # Raises error if only one allowable byte is given
    with pytest.raises(ValueError):
        oracle, _ = CBCoracle_FixedIV(rng.randbytes(16))
        diagnose_mode(oracle, 16, allowable_bytes=b'a')

    # Raises error if variable IV is used.
    with pytest.raises(RuntimeError):
        oracle, _ = CBCoracle('aes')
        diagnose_mode(oracle, 16)

    # Additional plaintext and quoting characters should not alter results of function:
    def build_additional_plaintext_oracle(oracle):
        prefix = b'email='
        suffix = b'&UID=10&role=user'
        quote_chars = b'=&'

        def new_oracle(message: bytes) -> bytes:
            for c in quote_chars:
                b = bytes([c])
                message = message.replace(b, b'"' + b + b'"')
            return oracle(prefix + message + suffix)
        return new_oracle

    allowable_bytes = bytes(set(range(256)) - set([ord('&'), ord('=')]))
    for mode, oracle in modes.items():
        additional_plaintext_oracle = build_additional_plaintext_oracle(oracle)
        assert diagnose_mode(additional_plaintext_oracle, 16, prefix_length=len(
            b'email='), allowable_bytes=allowable_bytes) == mode


def test_decrypt_suffix():
    rng = random.Random(12345)

    def build_additional_plaintext_oracle(encryption_oracle, prefix, suffix):

        def new_oracle(message: bytes) -> bytes:
            return encryption_oracle(prefix + message + suffix)
        return new_oracle

    true_prefix = b'abcdef'
    true_suffix = b'ghijklmno'

    oracle = build_additional_plaintext_oracle(
        ECBoracle('aes', rng.randbytes(16))[0],
        true_prefix,
        true_suffix)
    suffix = decrypt_suffix(oracle, len(true_suffix), len(true_prefix), 16)
    assert suffix == true_suffix

    oracle = build_additional_plaintext_oracle(
        CBCoracle_FixedIV(rng.randbytes(16))[0],
        true_prefix,
        true_suffix)
    suffix = decrypt_suffix(oracle, len(true_suffix), len(true_prefix), 16)
    assert suffix == true_suffix
    with pytest.raises(RuntimeError):
        decrypt_suffix(oracle, len(true_suffix),
                       len(true_prefix), 16, b'qwer')

    # Doesn't work if the IV changes.
    oracle = build_additional_plaintext_oracle(
        CBCoracle('aes', rng.randbytes(16))[0],
        true_prefix,
        true_suffix)
    with pytest.raises(RuntimeError):
        decrypt_suffix(oracle, len(true_suffix), len(true_prefix), 16)
