import json
import numpy as np
from cryptolib.maths.lattices import close_vector_problem
from pwn import *

def json_recv(remote):
    line = remote.recvline()
    return json.loads(line.decode())

def json_send(hsh, remote):
    request = json.dumps(hsh).encode()
    remote.sendline(request)

def main():
    r = remote('socket.cryptohack.org', 13390, level = 'debug')
    r.recvline()
    def reset():
        hsh = {"option": "reset"}
        json_send(hsh, r)
        json_recv(r)
    def get_sample():
        hsh = {"option": "get_sample"}
        json_send(hsh, r)
        return json_recv(r)

    n = 28
    A = []
    b = []
    samples = set()
    for _ in range(n):
        s = get_sample()
        this_a = tuple(s['a'])
        this_b = s['b']
        while (this_a,this_b) in samples:
            reset()
            s = get_sample()
            this_a = tuple(s['a'])
            this_b = s['b']
        samples.add((this_a,this_b))
        A.append(this_a)
        b.append(this_b)
        reset()

    # json_send(to_send, r)
    # received = json_recv(r)
    # n = len(received["a"])
    # A = []
    # A.append(received["a"])
    # b = []
    # b.append(received["b"])
    # for _ in range(n-1):
    #     json_send(to_send, r)
    #     received = json_recv(r)
    #     A.append(received["a"])
    #     b.append(received["b"])
    A = np.array(A)
    b = np.array(b)
    q = 127
    gamma = 10000 # Weight so that we get the correct small vector out
    L = np.block([
        [gamma*q*np.eye(n), np.zeros((n,n))],
        [          gamma*A,       np.eye(n)]
    ])
    target = np.block([gamma*b, np.zeros(n)])
    cv = close_vector_problem(L, target)
    print(cv)

if __name__ == "__main__":
    main()