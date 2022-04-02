import pytest
import random
from Crypto.Cipher import AES

from cryptolib.blockciphers.chosen_plain.attacks import get_block_size, diagnose_mode, get_additional_message_len, decrypt_suffix
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC_key_as_iv, EncryptECB, EncryptCBC, EncryptCFB, EncryptOFB, EncryptCBC_fixed_iv, EncryptCFB_fixed_iv, EncryptOFB_fixed_iv
from cryptolib.utils.padding import pkcs7

def test_oracles():
    rng = random.Random(12345)

    key_lens = [16] * 10 + [24] * 10 + [32] * 10

    # Test ECB mode
    for key_len in key_lens:
        key = rng.randbytes(key_len)

        reference_cipher = AES.new(key, AES.MODE_ECB)
        oracle = EncryptECB('aes', key)

        message = rng.randbytes(48)
        enc_message = oracle(message)
        expected_out = reference_cipher.encrypt(pkcs7(message, 16))
        assert enc_message == expected_out

    # Test CBC and OFB
    modes = {
        'cbc': (EncryptCBC, AES.MODE_CBC), 
        'ofb': (EncryptOFB, AES.MODE_OFB)
    }
    for key_len in key_lens:
        for _, objects in modes.items():
            oracle_constructor = objects[0]
            reference_mode = objects[1]

            key = rng.randbytes(key_len)

            oracle = oracle_constructor('aes', key)

            message = rng.randbytes(48)
            enc_message = oracle(message)
            iv = enc_message[:16]

            reference_cipher = AES.new(key, reference_mode, iv)
            expected_out = reference_cipher.encrypt(pkcs7(message, 16))
            assert enc_message[16:] == expected_out

    # Test CFB
    for key_len in key_lens:
        key = rng.randbytes(key_len)

        oracle = EncryptCFB('aes', key)

        message = rng.randbytes(48)
        enc_message = oracle(message)

        iv = enc_message[:16]
        reference_cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        expected_out = reference_cipher.encrypt(pkcs7(message, 16))
        assert enc_message[16:] == expected_out

    # Test key as IV oracle
    for key_len in key_lens:
        key = rng.randbytes(key_len)

        oracle = EncryptCBC_key_as_iv('aes', key)

        message = rng.randbytes(48)
        enc_message = oracle(message)

        reference_cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
        expected_out = reference_cipher.encrypt(pkcs7(message, 16))
        assert enc_message == expected_out

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

def test_diagnose_mode():
    rng = random.Random(12345)
    key = rng.randbytes(16)
    modes = {
        'cbc': EncryptCBC_fixed_iv, 
        'cfb': EncryptCFB_fixed_iv,
        'ecb': EncryptECB, 
        'stream': EncryptOFB_fixed_iv
    }
    for mode, constructor in modes.items():
        oracle = constructor('aes', key)
        assert diagnose_mode(oracle, 16) == mode

    # Check that probabilistic approach to CBC checking is working.
    for _ in range(100):
        key = rng.randbytes(16)
        oracle = EncryptCBC_fixed_iv('aes', key)
        assert diagnose_mode(oracle, 16) == 'cbc'

    # Raises error if only one allowable byte is given
    with pytest.raises(ValueError):
        oracle = EncryptCBC_fixed_iv('aes')
        diagnose_mode(oracle, 16, allowable_bytes= b'a')

    # Raises error if variable IV is used.
    with pytest.raises(RuntimeError):
        oracle = EncryptCFB('aes')
        diagnose_mode(oracle, 16)

    # Additional plaintext and quoting characters should not alter results of function:
    class additional_plaintext_oracle:
        def __init__(self, engine_constructor):
            self.engine = engine_constructor('aes', key)
            self.prefix = b'email='
            self.suffix = b'&UID=10&role=user'
            self.quote_chars = b'=&'
        def __call__(self, message: bytes) -> bytes:
            for c in self.quote_chars:
                b = bytes([c])
                message = message.replace(b, b'"' + b + b'"')
            return self.engine(self.prefix + message + self.suffix)

    allowable_bytes = bytes(set(range(256)) - set([ord('&'), ord('=')]))
    for mode, constructor in modes.items():
        oracle = additional_plaintext_oracle(constructor)
        assert diagnose_mode(oracle, 16, prefix_length=len(oracle.prefix), allowable_bytes=allowable_bytes) == mode

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
    