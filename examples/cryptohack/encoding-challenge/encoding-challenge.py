from pwn import * # pip install pwntools
from base64 import b64decode
import codecs
import json

r = remote('socket.cryptohack.org', 13377, level = 'debug')


def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for _ in range(100):
    received = json_recv()
    # print("Received type: ")
    # print(received["type"])
    # print("Received encoded value: ")
    # print(received["encoded"])

    encoded = received['encoded']

    if received["type"] == "base64":
        decoded = str(b64decode(encoded), 'utf-8')
    elif received["type"] == "hex":
        decoded = str(bytes.fromhex(encoded), 'utf-8')
    elif received["type"] == "rot13":
        decoded = codecs.decode(encoded, encoding="rot13")
    elif received["type"] == "bigint":
        decoded = int(encoded, 16).to_bytes(100, 'big').strip(b'\x00')
        decoded = str(decoded, 'utf-8')
        # decoded = int(received["encoded"])
        # strlen = len(hex(decoded)) // 2
        # decoded = str(decoded.to_bytes(strlen, 'big'), 'utf-8')
    elif received["type"] == "utf-8":
        decoded = str(bytes(received["encoded"]), 'utf-8')

    to_send = {
        "decoded": decoded
    }
    json_send(to_send)

received = json_recv()
print(received['flag'])
