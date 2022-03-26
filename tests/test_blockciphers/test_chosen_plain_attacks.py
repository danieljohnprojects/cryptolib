import pytest
import random

from cryptolib.blockciphers.chosen_plain.attacks import get_block_size, diagnose_mode, get_additional_message_len, decrypt_suffix
from cryptolib.blockciphers.chosen_plain.oracles import EncryptECB, EncryptCBC, EncryptCFB, EncryptOFB, EncryptCBC_fixed_iv, EncryptCFB_fixed_iv, EncryptOFB_fixed_iv
from cryptolib.utils.padding import pkcs7


def test_get_block_size():
    rng = random.Random(12345)
    oracle = EncryptECB('aes', rng.randbytes(16))
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


def test_diagnose_mode():
    rng = random.Random(12345)
    key = rng.randbytes(16)
    modes = {
        'cbc': EncryptCBC_fixed_iv, 
        'cfb': EncryptCFB_fixed_iv,
        'ecb': EncryptECB, 
        'ofb': EncryptOFB_fixed_iv
    }
    for mode, constructor in modes.items():
        oracle = constructor('aes', key)
        assert diagnose_mode(oracle, 16) == mode
    with pytest.raises(ValueError):
        oracle = EncryptCBC_fixed_iv('aes')
        diagnose_mode(oracle, 16, b'a')
    with pytest.raises(RuntimeError):
        oracle = EncryptCFB('aes')
        diagnose_mode(oracle, 16)


def test_get_additional_message_len():
    rng = random.Random(12345)

    class additional_plaintext_oracle_ecb:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptECB('aes', key)

        def __call__(self, message: bytes) -> bytes:
            return self.engine(self.prefix + message + self.suffix)

    class additional_plaintext_oracle_cbc_fixed_iv:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptCBC_fixed_iv('aes', key)

        def __call__(self, message: bytes) -> bytes:
            # Don't forget to remove the IV.
            return self.engine(self.prefix + message + self.suffix)[16:]

    class additional_plaintext_oracle_cbc:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptCBC('aes', key)

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
    

def test_decrypt_suffix():
    rng = random.Random(12345)

    class additional_plaintext_oracle_ecb:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptECB('aes', key)

        def __call__(self, message: bytes) -> bytes:
            return self.engine(self.prefix + message + self.suffix)

    class additional_plaintext_oracle_cbc_fixed_iv:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptCBC_fixed_iv('aes', key)

        def __call__(self, message: bytes) -> bytes:
            # Don't forget to remove the IV.
            return self.engine(self.prefix + message + self.suffix)[16:]

    class additional_plaintext_oracle_cbc:
        def __init__(self):
            key = rng.randbytes(16)
            self.prefix = b'abcdef'
            self.suffix = b'ghijklmno'
            self.engine = EncryptCBC('aes', key)

        def __call__(self, message: bytes) -> bytes:
            # Don't forget to remove the IV.
            return self.engine(self.prefix + message + self.suffix)[16:]

    oracle = additional_plaintext_oracle_ecb()
    suffix = decrypt_suffix(oracle, len(oracle.suffix), len(oracle.prefix), 16)
    assert suffix == oracle.suffix

    oracle = additional_plaintext_oracle_cbc_fixed_iv()
    suffix = decrypt_suffix(oracle, len(oracle.suffix), len(oracle.prefix), 16)
    assert suffix == oracle.suffix
    with pytest.raises(RuntimeError):
        decrypt_suffix(oracle, len(oracle.suffix), len(oracle.prefix), 16, b'qwer')

    oracle = additional_plaintext_oracle_cbc()
    with pytest.raises(RuntimeError):
        decrypt_suffix(oracle, len(oracle.suffix), len(oracle.prefix), 16)
    
    