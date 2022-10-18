# Cryptolib
Cryptolib is a library for solving cryptanalysis challenges in capture the flags (CTFs).
The attacks in this library are intended for educational purposes only, ***do not*** use them to exploit a real world system.
In keeping with the educational theme the attack implementations are not designed to be highly efficient and in some cases are not particularly reliable. 

For examples of using the library see the `tests/test_cryptopals` directory.
Here I have included solutions to the first four sets of challenges.
I strongly recommend that you solve the challenges yourself before looking at these tests.

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