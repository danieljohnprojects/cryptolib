import codecs
import string

from pwn import *

from cryptolib.pipes import Pipe
from cryptolib.cracks.bc_oracles import uses_ECB, get_block_size, get_additional_message_len, decode_suffix

class ForeverCTF_AES_Oracle(Pipe):
    def __init__(self, **kwargs):
        host = 'forever.isss.io'
        port = 3103
        conn = remote(host, port)
        kwargs['conn'] = conn
        super().__init__(**kwargs)
    
    def __call__(self, message: bytes) -> bytes:
        conn = self.state['conn']
        l = conn.recvline() # Send me a message >:)
        conn.sendline(message)
        l = conn.recvline() # Here's your encrypted message with the flag! Too bad you can't read it now >:D
        return codecs.decode(conn.recvline(keepends=False), 'hex_codec')

oracle = ForeverCTF_AES_Oracle()
allowable_bytes = bytes(string.printable[:-5], encoding='ascii')
block_size = get_block_size(oracle, allowable_bytes=allowable_bytes)
print(f"Block size: {block_size}") # 16
print(f"ECB mode: {uses_ECB(oracle, block_size=block_size, allowable_bytes=allowable_bytes)}") # True

prefix_len, suffix_len = get_additional_message_len(oracle, block_size, allowable_bytes=allowable_bytes)
print(f"Prefix length: {prefix_len}") # 0
print(f"Suffix length: {suffix_len}") # 41

suffix = decode_suffix(oracle, suffix_len=suffix_len, prefix_len=prefix_len, block_size=block_size, allowable_bytes=allowable_bytes)
print(f"Suffix: {suffix}") # utflag{0nly_5ecur3_1f_y0u_us3_1t_pr0p3r1y

oracle.state['conn'].close()