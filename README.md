# Cryptolib
Cryptolib is a library for solving cryptanalysis challenges in capture the flags (CTFs).
The attacks in this library are intended for educational purposes only, ***do not*** use them to exploit a real world system.
In keeping with the educational theme the attack implementations are not designed to be highly efficient and in some cases are not particularly reliable. 

For examples of using the library see the `tests/test_cryptopals` directory.
Here I have included solutions to the first four sets of challenges.
I strongly recommend that you solve the challenges yourself before looking at these tests.

# Code structure
The actual code is split into two directories:
   - `cryptolib` contains the python functions and classes with which you should interact.
   - `lib` contains C implementations of some low level crypt primitives. 
   These are not really intended to be used directly but you can have a poke around in there if you're really curious.

The python functions and classes in the `cryptolib` directory are divided into modules based on cryptographic primitives.
For example in `cryptolib/blockciphers` you will find an implementation of AES, encryption and decryption oracles, and attacks on common misimplementations.

The structure of the code inside `cryptolib` has changed several times and will likely change again.
The code in `lib` is probably going to be more stable.

One day I'll get around to writing some more examples but in the mean time the solutions to the cryptopals challenges in `tests/test_cryptopals` should hopefully provide enough examples to use the functions effectively.

# Install instructions
First clone this directory, navigate into it, and then:

```
sudo apt install python3.9-venv
python3.9 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
pip install -e .

sudo apt install cmake
mkdir build
cd build
cmake ..
make

cd ..
pytest tests
```