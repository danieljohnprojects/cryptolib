# Install instructions

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