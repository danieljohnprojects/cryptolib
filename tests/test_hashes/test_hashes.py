import pytest

import random

from cryptolib.hashes.SHA1 import sha1digest, sha1extend
from cryptolib.hashes.MD2 import md2digest
from cryptolib.hashes.MD4 import md4digest
from cryptolib.hashes.MD5 import md5digest
from Crypto.Hash import SHA1, MD2, MD4, MD5

def test_sha1digest():
    rng = random.Random(12345)

    assert sha1digest(b'abc') == bytes.fromhex('a9993e364706816aba3e25717850c26c9cd0d89d')
    
    assert sha1digest(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq') == bytes.fromhex('84983e441c3bd26ebaae4aa1f95129e5e54670f1')
    
    h = SHA1.new(b'')
    assert sha1digest(b'') == h.digest()

    for _ in range(20):
        l = rng.randint(0, 300)
        message = rng.randbytes(l)
        h = SHA1.new(message)
        assert h.digest() == sha1digest(message)

def test_md2digest():
    rng = random.Random(12345)

    assert md2digest(b'') == bytes.fromhex('8350e5a3e24c153df2275c9f80692773')
    assert md2digest(b'a') == bytes.fromhex('32ec01ec4a6dac72c0ab96fb34c0b5d1')
    assert md2digest(b'abc') == bytes.fromhex('da853b0d3f88d99b30283a69e6ded6bb')
    assert md2digest(b'message digest') == bytes.fromhex('ab4f496bfb2a530b219ff33031fe06b0')
    assert md2digest(b'abcdefghijklmnopqrstuvwxyz') == bytes.fromhex('4e8ddff3650292ab5a4108c3aa47940b')
    assert md2digest(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') == bytes.fromhex('da33def2a42df13975352846c30338cd')
    assert md2digest(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890') == bytes.fromhex('d5976f79d83d3a0dc9806c3c66f3efd8')
    
    for _ in range(20):
        l = rng.randint(0, 300)
        message = rng.randbytes(l)
        h = MD2.new(message)
        assert h.digest() == md2digest(message)

def test_md4digest():
    rng = random.Random(12345)

    assert md4digest(b'') == bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
    assert md4digest(b'a') == bytes.fromhex('bde52cb31de33e46245e05fbdbd6fb24')
    assert md4digest(b'abc') == bytes.fromhex('a448017aaf21d8525fc10ae87aa6729d')
    assert md4digest(b'message digest') == bytes.fromhex('d9130a8164549fe818874806e1c7014b')
    assert md4digest(b'abcdefghijklmnopqrstuvwxyz') == bytes.fromhex('d79e1c308aa5bbcdeea8ed63df412da9')
    assert md4digest(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') == bytes.fromhex('043f8582f241db351ce627e153e7f0e4')
    assert md4digest(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890') == bytes.fromhex('e33b4ddc9c38f2199c3e7b164fcc0536')
    
    for _ in range(20):
        l = rng.randint(0, 300)
        message = rng.randbytes(l)
        h = MD4.new(message)
        assert h.digest() == md4digest(message)

def test_md5digest():
    rng = random.Random(12345)

    assert md5digest(b'') == bytes.fromhex('d41d8cd98f00b204e9800998ecf8427e')
    assert md5digest(b'a') == bytes.fromhex('0cc175b9c0f1b6a831c399e269772661')
    assert md5digest(b'abc') == bytes.fromhex('900150983cd24fb0d6963f7d28e17f72')
    assert md5digest(b'message digest') == bytes.fromhex('f96b697d7cb7938d525a2f31aaf161d0')
    assert md5digest(b'abcdefghijklmnopqrstuvwxyz') == bytes.fromhex('c3fcd3d76192e4007dfb496cca67e13b')
    assert md5digest(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') == bytes.fromhex('d174ab98d277d9f5a5611c2c9f419d9f')
    assert md5digest(b'12345678901234567890123456789012345678901234567890123456789012345678901234567890') == bytes.fromhex('57edf4a22be3c955ac49da2e2107b67a')
    
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