from typing import Callable


class Oracle():
    def __init__(self, func: Callable):
        self.func = func

    def __call__(self, message: bytes) -> bytes:
        return self.func(message)
