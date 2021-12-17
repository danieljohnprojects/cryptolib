from typing import Callable, Sequence
from ..pipes import Pipe


class SequentialOracle(Pipe):
    """
    A pipeline of components each taking and returning a byte string.

    An oracle takes in some input and divines from it some output. After instantiation an oracle object should be treated like a black box and should only be interacting with by calling the oracle on data. Ideally an oracle should have no other easily accesible methods.

    In practice other methods may be necessary for example to change the IV ov an encryption pipe.

    A lot of behaviour will be duplicated across oracles. To facilitate this oracles are instantiated with a pipeline. Each component of the pipeline will be called in turn, passing the output of each component to the next as input.
    """

    def __init__(self, pipeline: Sequence[Callable], **kwargs):
        """Initialise an oracle using the given sequence of pipes."""
        kwargs['pipeline'] = pipeline
        super().__init__(**kwargs)
        
        for pipe in self.state['pipeline']:
            if isinstance(pipe, Pipe):
                pipe.state['parent'] = self

    def prepend_pipe(self, pipe: Callable):
        """Adds a pipe to the beginning of the pipeline."""
        if isinstance(pipe, Pipe):
            pipe.state['parent'] = self
        self.state['pipeline'] = [pipe] + self.state['pipeline']

    def append_pipe(self, pipe: Callable):
        """Adds a pipe to the end of the pipeline."""
        if isinstance(pipe, Pipe):
            pipe.state['parent'] = self
        self.state['pipeline'] += [pipe]

    def __call__(self, message: bytes) -> bytes:
        """Call each pipe in the pipeline, passing the output from one as input to the next."""
        for pipe in self.state['pipeline']:
            message = pipe(message)
        return message
