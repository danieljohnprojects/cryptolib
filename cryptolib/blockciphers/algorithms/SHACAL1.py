from ctypes import *
from .BCEngine import BCEngine
from ...utils.files import build_filename

block_t = c_uint32 * 5
key_t = c_uint32 * 4
key_schedule_t = c_uint32 * 80
class SHACAL1(BCEngine):
    libpath = build_filename('build/lib/SHACAL/libshacal1.so')
    SHACAL1libC = CDLL(libpath)
    
    block_size = 20
    
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError(
                f"Key must be between 16 bytes long, got {len(key)}."
            )
        key = key_t(
            int.from_bytes(key[  : 4], 'big', signed=False),
            int.from_bytes(key[ 4: 8], 'big', signed=False),
            int.from_bytes(key[ 8:12], 'big', signed=False),
            int.from_bytes(key[12:  ], 'big', signed=False),
        )
        self._key_schedule = key_schedule_t(*[0 for _ in range(80)])
        self.SHACAL1libC.initialise_key(key, self._key_schedule)
    
    def encrypt(self, message: bytes) -> bytes:
        if len(message) != self.block_size:
            raise ValueError(f"Message length must be {block_size} bytes long. Got {len(message)}.")
        block = block_t(
            int.from_bytes(message[  : 4], 'big', signed=False),
            int.from_bytes(message[ 4: 8], 'big', signed=False),
            int.from_bytes(message[ 8:12], 'big', signed=False),
            int.from_bytes(message[12:16], 'big', signed=False),
            int.from_bytes(message[16:  ], 'big', signed=False),
        )
        self.SHACAL1libC.encrypt(self._key_schedule, block)
        return b''.join([block[i].to_bytes(4, 'little') for i in range(5)])
        
    def decrypt(self, message: bytes) -> bytes:
        if len(message) != self.block_size:
            raise ValueError(f"Message length must be {block_size} bytes long. Got {len(message)}.")
        block = block_t(
            int.from_bytes(message[  : 4], 'little', signed=False),
            int.from_bytes(message[ 4: 8], 'little', signed=False),
            int.from_bytes(message[ 8:12], 'little', signed=False),
            int.from_bytes(message[12:16], 'little', signed=False),
            int.from_bytes(message[16:  ], 'little', signed=False),
        )
        self.SHACAL1libC.decrypt(self._key_schedule, block)
        return b''.join([block[i].to_bytes(4, 'big') for i in range(5)])
        