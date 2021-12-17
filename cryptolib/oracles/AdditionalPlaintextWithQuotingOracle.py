from typing import Optional

from .AdditionalPlaintextOracle import AdditionalPlaintextOracle


class AdditionalPlaintextWithQuotingOracle(AdditionalPlaintextOracle):
    """
    Takes in a message, quotes out specific characters, prepends a secret prefix, appends a secret suffix, pads it, and encrypts it with a fixed key in the specified mode.

    If no key is provided one is randomly generated.
    """

    def __init__(self, quote_chars: bytes = b'', **kwargs):
        
        super().__init__(**kwargs)
        for char in quote_chars:
            b = bytes([char])
            self.prepend_pipe(
                lambda message: message.replace(b, b'"' + b + b'"')
            )
