from typing import Callable, Sequence

class Oracle():
    """A pipeline of components each taking and returning a byte string.

    An oracle takes in some input and divines from it some output from it. After instantiation an oracle object should be treated like a black box. All interaction should generally be with the divine method. Ideally an oracle should have no other easily accesible methods.

    In practice other methods may be necessary for example to change the IV ov an encryption pipe.

    A lot of behaviour will be duplicated across oracles. To facilitate this oracles are instantiated with a pipeline. Each component of the pipeline will be called in turn, passing the output of each component to the next as input.
    """
    
    def __init__(self, pipeline: Sequence[Callable]):
        self.pipeline = pipeline

    def divine(self, message: bytes) -> bytes:
        for pipe in self.pipeline:
            message = pipe(message)
        return message