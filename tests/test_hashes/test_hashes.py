import pytest

import random

from cryptolib.hashes.SHA1 import sha1digest, sha1extend, sha1extend_message
from cryptolib.hashes.SHA2 import sha256digest, sha224digest, sha256extend, sha256extend_message
from cryptolib.hashes.MD2 import md2digest
from cryptolib.hashes.MD4 import md4digest, md4extend, md4extend_message
from cryptolib.hashes.MD5 import md5digest, md5extend, md5extend_message
from cryptolib.hashes.MAC import prefixMAC, HMAC
from Crypto.Hash import SHA1, SHA256, SHA224, MD2, MD4, MD5

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
    

def test_sha256digest():
    test_answers = [
        bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        bytes.fromhex('ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'),
        bytes.fromhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        bytes.fromhex('f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650'),
        bytes.fromhex('71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73'),
        bytes.fromhex('db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0'),
        bytes.fromhex('f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e'),
        bytes.fromhex('41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3'),
        bytes.fromhex('27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711'),
    ]
    ref = lambda m: SHA256.new(m).digest()
    hash_test(sha256digest, ref, test_answers)

def test_sha224digest():
    test_answers = [
        bytes.fromhex('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'),
        bytes.fromhex('abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5'),
        bytes.fromhex('23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'),
        bytes.fromhex('2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb'),
        bytes.fromhex('45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2'),
        bytes.fromhex('bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9'),
        bytes.fromhex('b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e'),
        bytes.fromhex('4e8f0ce90b64661a2b5e84be6d93a7d9b76871062f1814433d04a03d'),
        bytes.fromhex('00568fba93e8718c2f7dcd82fa94501d59bb1bbcba2c7dc2ba5882db'),
    ]
    ref = lambda m: SHA224.new(m).digest()
    hash_test(sha224digest, ref, test_answers)

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
        