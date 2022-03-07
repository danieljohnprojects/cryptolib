from math import ceil

from ..pipes import Pipe


def exhaust(
        target_output: bytes,
        pipeline: Pipe,
        bits: int
    ) -> int:
    """
    Takes a target byte sequence and searches over all byte sequences up to the specified number of bits for something that matches the target after running through the pipeline.

    This is a simple exhaust with no special gadgets. Any processing of the bits must happen in the pipeline. 

    Inputs:
        The target output of the pipeline.
        The pipeline to be applied to candidate inputs.
        The number of bits to use as input.

    Output:
    The input value that produces matching output. Raises an error if no input was found.
    """

    if not isinstance(bits, int):
        raise ValueError(f"bits argument must be of type int. Got {type(bits)}.")
    if bits < 1 or bits > 64:
        raise ValueError(f"bits argument must be a positive integer less than 65.")

    # Could parallelise this for loop
    for candidate in range(2**bits):
        cand_bytes = candidate.to_bytes(ceil(bits/8), 'big')
        if pipeline(cand_bytes) == target_output:
            return cand_bytes
    else:
        raise RuntimeError("No input found matching target output.")
