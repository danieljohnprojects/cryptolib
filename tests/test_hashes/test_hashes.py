import pytest

import random

from cryptolib.hashes.SHA1 import sha1digest, sha1extend, sha1extend_message
from cryptolib.hashes.MD2 import md2digest
from cryptolib.hashes.MD4 import md4digest, md4extend, md4extend_message
from cryptolib.hashes.MD5 import md5digest, md5extend, md5extend_message
from cryptolib.hashes.MAC import prefixMAC, HMAC
from Crypto.Hash import SHA1, MD2, MD4, MD5

test_vectors = [
    b'',
    b'a',
    b'abc',
    b'message digest',
    b'abcdefghijklmnopqrstuvwxyz',
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    b'12345678901234567890123456789012345678901234567890123456789012345678901234567890',
    b'a' * 1000,
    b'a' * 10000,
]

def hash_test(hash_fn, reference_hash_fn, test_answers):
    rng = random.Random(12345)
    for t, a in zip(test_vectors, test_answers):
        assert hash_fn(t) == a
    for l in range(5000):
        m = rng.randbytes(l)
        assert hash_fn(m) == reference_hash_fn(m)
    with pytest.raises(TypeError):
        hash_fn('abc')
    
def test_sha1digest():
    test_answers = [
        bytes.fromhex('da39a3ee5e6b4b0d3255bfef95601890afd80709'),
        bytes.fromhex('86f7e437faa5a7fce15d1ddcb9eaeaea377667b8'),
        bytes.fromhex('a9993e364706816aba3e25717850c26c9cd0d89d'),
        bytes.fromhex('c12252ceda8be8994d5fa0290a47231c1d16aae3'),
        bytes.fromhex('32d10c7b8cf96570ca04ce37f2a19d84240d3a89'),
        bytes.fromhex('761c457bf73b14d27e9e9265c46f4b4dda11f940'),
        bytes.fromhex('50abf5706a150990a08b2c5ea40fa0e585554732'),
        bytes.fromhex('291e9a6c66994949b57ba5e650361e98fc36b1ba'),
        bytes.fromhex('a080cbda64850abb7b7f67ee875ba068074ff6fe'),
    ]
    ref = lambda m: SHA1.new(m).digest()
    hash_test(sha1digest, ref, test_answers)
    
    assert sha1digest(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq') == bytes.fromhex('84983e441c3bd26ebaae4aa1f95129e5e54670f1')
    
    h = SHA1.new(b'')
    assert sha1digest(b'') == h.digest()

    for _ in range(20):
        l = rng.randint(0, 300)
        message = rng.randbytes(l)
        h = SHA1.new(message)
        assert h.digest() == sha1digest(message)

    with pytest.raises(TypeError):
        sha1digest('abc')

def test_md2digest():
    test_answers = [
        bytes.fromhex('8350e5a3e24c153df2275c9f80692773'),
        bytes.fromhex('32ec01ec4a6dac72c0ab96fb34c0b5d1'),
        bytes.fromhex('da853b0d3f88d99b30283a69e6ded6bb'),
        bytes.fromhex('ab4f496bfb2a530b219ff33031fe06b0'),
        bytes.fromhex('4e8ddff3650292ab5a4108c3aa47940b'),
        bytes.fromhex('da33def2a42df13975352846c30338cd'),
        bytes.fromhex('d5976f79d83d3a0dc9806c3c66f3efd8'),
        bytes.fromhex('dd21a412ef3f285fd1f2e70a6c10a702'),
        bytes.fromhex('f1c21e9a0a162c8dfc4adb86b3dca7f2'),
    ]
    ref = lambda m: MD2.new(m).digest()
    hash_test(md2digest, ref, test_answers)
    
def test_md4digest():
    test_answers = [
        bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0'),
        bytes.fromhex('bde52cb31de33e46245e05fbdbd6fb24'),
        bytes.fromhex('a448017aaf21d8525fc10ae87aa6729d'),
        bytes.fromhex('d9130a8164549fe818874806e1c7014b'),
        bytes.fromhex('d79e1c308aa5bbcdeea8ed63df412da9'),
        bytes.fromhex('043f8582f241db351ce627e153e7f0e4'),
        bytes.fromhex('e33b4ddc9c38f2199c3e7b164fcc0536'),
        bytes.fromhex('5f1bf26a8067c9159b91f1440f7c9e8a'),
        bytes.fromhex('9c88157a6f588e9815a9e6b60877d93e'),
    ]
    ref = lambda m: MD4.new(m).digest()
    hash_test(md4digest, ref, test_answers)

def test_md5digest():
    test_answers = [
        bytes.fromhex('d41d8cd98f00b204e9800998ecf8427e'),
        bytes.fromhex('0cc175b9c0f1b6a831c399e269772661'),
        bytes.fromhex('900150983cd24fb0d6963f7d28e17f72'),
        bytes.fromhex('f96b697d7cb7938d525a2f31aaf161d0'),
        bytes.fromhex('c3fcd3d76192e4007dfb496cca67e13b'),
        bytes.fromhex('d174ab98d277d9f5a5611c2c9f419d9f'),
        bytes.fromhex('57edf4a22be3c955ac49da2e2107b67a'),
        bytes.fromhex('cabe45dcc9ae5b66ba86600cca6b8ba8'),
        bytes.fromhex('0d0c9c4db6953fee9e03f528cafd7d3e'),
    ]
    ref = lambda m: MD5.new(m).digest()
    hash_test(md5digest, ref, test_answers)
    
    for _ in range(20):
        l = rng.randint(0, 300)
        message = rng.randbytes(l)
        h = MD5.new(message)
        assert h.digest() == md5digest(message)

def test_sha1extend():
    # Extend hash of 'abc'
    original_message = b'abc'
    original_hash = sha1digest(original_message)

    extensions = [b'abc', b'', b'def', b'abcdefghijklmnopqrstuvwxyz']
    for ext in extensions:
        assert sha1extend(original_hash, len(original_message), ext) == sha1digest(b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18' + ext)
        with pytest.raises(TypeError):
            sha1digest(str(ext, 'ascii'))

def test_sha1extend_message():
    original_message = b'abc'
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18'
    assert sha1extend_message(0, original_message, b'') == padded_message
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20'
    assert sha1extend_message(1, original_message, b'') == padded_message

def test_md4extend():
    # Extend hash of 'abc'
    original_message = b'abc'
    original_hash = md4digest(original_message)

    extensions = [b'abc', b'', b'def', b'abcdefghijklmnopqrstuvwxyz']
    for ext in extensions:
        assert md4extend(original_hash, len(original_message), ext) == md4digest(b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00' + ext)
        with pytest.raises(TypeError):
            md4digest(str(ext, 'ascii'))

def test_md4extend_message():
    original_message = b'abc'
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00'
    assert md4extend_message(0, original_message, b'') == padded_message
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00'
    assert md4extend_message(1, original_message, b'') == padded_message

def test_md5extend():
    # Extend hash of 'abc'
    original_message = b'abc'
    original_hash = md5digest(original_message)

    extensions = [b'abc', b'', b'def', b'abcdefghijklmnopqrstuvwxyz']
    for ext in extensions:
        assert md5extend(original_hash, len(original_message), ext) == md5digest(b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00' + ext)
        with pytest.raises(TypeError):
            md5digest(str(ext, 'ascii'))

def test_md5extend_message():
    original_message = b'abc'
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00'
    assert md5extend_message(0, original_message, b'') == padded_message
    padded_message = b'abc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00'
    assert md5extend_message(1, original_message, b'') == padded_message

def test_MACs():
    rng = random.Random(12345)
    
    sign, verify = prefixMAC(sha1digest, rng.randbytes(16))
    messages = [b'', b'a', b'hello', b'a'*1000]
    for message in messages:
        mac = sign(message)
        assert verify(message, mac)
        assert not verify(message, b'')
        assert not verify(message, b'a')
        assert not verify(message, bytes(len(sha1digest(b''))))
        