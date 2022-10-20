import pytest
import random
import sockets
from multiprocessing import Process, Queue
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC
from cryptolib.blockciphers.chosen_cipher.oracles import DecryptCBC
from cryptolib.publickey.DiffieHellman.implementations import modp2048
from .data import challenge34

def test_challenge33():
    keygen, shared_secret = modp2048()
    privAlice, pubAlice = keygen()
    privBob, pubBob = keygen()
    assert shared_secret(privAlice, pubBob) == shared_secret(privBob, pubAlice)

def test_challenge34():
    aliceAddress = b'cryptopal_alice_' + random.randbytes(8)
    bobAddress = b'cryptopal_bob_' + random.randbytes(8)
    malloryAddress = b'cryptonemesis_mallory_' + random.randbytes(8)
    
    def runMallory(malloryAddress: bytes, malloryMessage: bytes, aliceAddress: bytes, bobAddress: bytes):
        keygen, shared_secret = modp2048()
        privMallory, pubMallory = keygen()
        pubMallory = (pubMallory[0], pubMallory[1], pubMallory[0])
        with sockets.sock
    
    aliceMessage = b'I love you Bob!'
    malloryMessage = b'I love you Bob!'
    
    q = Queue()
    
    Alice = Process(target=challenge34.runAlice, args=(aliceAddress, aliceMessage, q))
    Mallory = Process(target=runMallory, args=(malloryAddress, malloryMessage, aliceAddress, bobAddress))
    Bob = Process(target=challenge34.runBob, args=(bobAddress, malloryAddress, q))
    
    Alice.start()
    Bob.start()
    Alice.join()
    Bob.join()
    assert q.get()
    assert q.get() == malloryMessage
    # assert False
    # keygen, shared_secret = modp2048()
    # privAlice, pubAlice = keygen()
    # privBob, pubBob = keygen()
    # ssBob = shared_secret(privBob, pubAlice)
    # ssAlice = shared_secret(privAlice, pubBob)
    # pubMallory = (pubAlice[0], pubAlice[1], pubAlice[0])
    