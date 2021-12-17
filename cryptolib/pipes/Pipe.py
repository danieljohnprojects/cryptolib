from abc import ABC, abstractmethod


class Pipe(ABC):
    """
    A pipe is essentially a function that maintains it's own state between calls.

    State is kept in a dictionary 

    For example you might use a pipe to encrypt a bunch of messages under AES with the same key. This saves you from redoing the key schedule each time. 

    When called, a pipe should take bytes as input, and return bytes as output. They are designed to so that multiple pipe can be chained together to form a pipeline.

    Pipes can contain other pipes, this is useful to facilitate communication of state parameters between pipes.
    """

    def __init__(self, **kwargs):
        self.state = kwargs

    @abstractmethod
    def __call__(self, message: bytes) -> bytes:
        pass
