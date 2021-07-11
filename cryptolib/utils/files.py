import os

def build_filename(filepath: str) -> str:
    """Return the complete file name for a file in the build directory.
    filepath : string
        The path to the file in the build directory.
        Must begin with "build".
    """

    if not filepath.startswith( "build" ):
        raise ValueError("Only available for build files")
    root_dir, _ = os.path.split(os.path.abspath(__file__)) # strip off file.py
    root_dir, _ = os.path.split(root_dir) # Strip off utils
    root_dir, _ = os.path.split(root_dir) # Strip off cryptolib

    return os.path.join(root_dir, filepath)