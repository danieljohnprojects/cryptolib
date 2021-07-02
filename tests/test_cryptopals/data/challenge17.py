import secrets

from base64 import b64decode
from typing import Tuple

from cryptolib.oracles import SequentialOracle
from cryptolib.pipes import BCDecrypt, BCEncrypt, PadPKCS7, StripPKCS7
from cryptolib.utils.conversion import b64_string_to_hex

plaintexts = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]

plaintexts = list(map(b64decode, plaintexts))


def create_server_client() -> Tuple[SequentialOracle, SequentialOracle]:
    key = secrets.token_bytes(24)
    client = SequentialOracle([
        PadPKCS7(),
        BCEncrypt(
            mode='cbc',
            algorithm='aes',
            key=key,
            iv=b'\x00'*16
        )
    ])
    server = SequentialOracle([
        BCDecrypt(
            mode='cbc',
            algorithm='aes',
            key=key,
            iv=b'\x00'*16
        )

    ])
    return server, client
