import pickle
import random
import socket
import time
from cryptolib.blockciphers.chosen_plain.oracles import EncryptCBC
from cryptolib.blockciphers.chosen_cipher.oracles import DecryptCBC
from cryptolib.publickey.DiffieHellman.implementations import modp2048

def runAlice(aliceAddress: bytes, aliceMessage: bytes, q):
    keygen, shared_secret = modp2048()
    privAlice, pubAlice = keygen()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.bind(aliceAddress)
        print(f"Listening on address: {aliceAddress}")
        s.listen(1)
        conn, bobAddress = s.accept()
        with conn:
            print(f'Connected by {bobAddress}')
            # Send public key
            conn.sendall(pickle.dumps(pubAlice))
            print("Alice's public key sent")
            # Receive Bob's public key
            pubBob = conn.recv(1024)
            pubBob = pickle.loads(pubBob)
            print("Bob's public key received")
            # Derive the secret symmetric key
            ss = shared_secret(privAlice, pubBob)
            key = ss[:16]
            # Send a message encrypted with the secret key
            bc = EncryptCBC('aes', key)
            conn.sendall(bc(aliceMessage))
            print("Secret message sent")
            # Recieve Bob's message
            bobsMessage = conn.recv(1024)
            bc = DecryptCBC('aes', key)
            print("Return message received")
    q.put(bc(bobsMessage) == aliceMessage)

def runBob(bobAddress: bytes, aliceAddress: bytes, q):
    keygen, shared_secret = modp2048()
    privBob, pubBob = keygen()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.bind(bobAddress)
        s.connect(aliceAddress)
        # Receive Alice's public key
        pubAlice = s.recv(1024) 
        pubAlice = pickle.loads(pubAlice)
        print("Alice's public key received")
        # Send public key
        s.sendall(pickle.dumps(pubBob))
        print("Public key sent")
        # Derive shared secret
        ss = shared_secret(privBob, pubAlice)
        key = ss[:16]
        bc = DecryptCBC('aes', key)
        # Receive encrypted message
        aliceMessage = s.recv(1024)
        aliceMessage = bc(aliceMessage)
        print("Secret message recieved")
        # Re-encrypt message and send
        bc = EncryptCBC('aes', key)
        s.send(bc(aliceMessage))
        print("Reply sent")
    time.sleep(0.01)
    q.put(aliceMessage)