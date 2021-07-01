from typing import Callable, Optional

class Pipe():
    """A blank component of an oracle pipeline.

    Designed to be extended to provide some form of functionality along an oracle pipeline. Only necessary requirement is a __call__ function which takes in a bytes object and returns a bytes object.
    """

    def __init__(self, func: Optional[Callable] = None):
        if func:
            self.func = func
        else:
            self.func = lambda message: message

    def __call__(self, message: bytes) -> bytes:
        return self.func(message)
