import codecs
import string

from pwn import *

from cryptolib.blockciphers.attacks.chosen_plain import get_block_size, diagnose_mode, get_additional_message_len, decrypt_suffix


class ForeverCTF_AES_Oracle:
    def __init__(self):
        host = 'forever.isss.io'
        port = 3103
        self.conn = remote(host, port)

    def __call__(self, message: bytes) -> bytes:
        l = self.conn.recvline()  # Send me a message >:)
        self.conn.sendline(message)
        # Here's your encrypted message with the flag! Too bad you can't read it now >:D
        l = self.conn.recvline()
        return codecs.decode(self.conn.recvline(keepends=False), 'hex_codec')


oracle = ForeverCTF_AES_Oracle()
allowable_bytes = bytes(string.printable[:-5], encoding='ascii')
print("Block size: ", end='')
B = get_block_size(oracle, allowable_bytes=allowable_bytes)
print(B)  # 16
print(f"Block cipher mode: ", end='')
mode = diagnose_mode(oracle, block_size=B, allowable_bytes=allowable_bytes)
print(mode)  # ecb

prefix_len, suffix_len = get_additional_message_len(
    oracle, B, allowable_bytes=allowable_bytes)
print(f"Prefix length: {prefix_len}")  # 0
print(f"Suffix length: {suffix_len}")  # 41

suffix = decrypt_suffix(oracle, suffix_len=suffix_len,
                        prefix_len=prefix_len, block_size=B, allowable_bytes=allowable_bytes)
print(f"Suffix: {suffix}")  # utflag{0nly_5ecur3_1f_y0u_us3_1t_pr0p3r1y

oracle.conn.close()
