from abc import ABC, abstractmethod


class Oracle(ABC):
    @abstractmethod
    def __init__(self, *args, **kwargs):
        pass

    @abstractmethod
    def __call__(self, message: bytes) -> bytes:
        pass
