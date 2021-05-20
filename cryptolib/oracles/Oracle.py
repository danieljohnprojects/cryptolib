from abc import ABC, abstractclassmethod

class Oracle(ABC):
    """
    An oracle takes in some input and divines some output from it.

    All interaction with an oracle by other objects should solely be through the divine method. It's behaviour should be viewed as a black box.
    """
    @abstractclassmethod
    def divine(self, *args, **kwargs):
        pass