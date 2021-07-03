from abc import ABC, abstractmethod


class Pipe(ABC):
    """
    An oracle is essentially a function that maintains it's own state between calls.

    State is kept in a dictionary 

    For example you might use an oracle to encrypt a bunch of message under AES with the same key. This saves you from redoing the key schedule each time. 

    When called, an oracle should take bytes as input, and return bytes as output. They are designed to so that multiple oracles can be chained together to form a pipeline.

    Oracles can contain other oracles, this is useful to facilitate communication of state parameters between oracles.
    """

    def __init__(self, **kwargs):
        self.state = kwargs

    @abstractmethod
    def __call__(self, message: bytes) -> bytes:
        pass
