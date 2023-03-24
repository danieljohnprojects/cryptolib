import secrets

from cryptolib.blockciphers.oracles import CBCoracle_KeyAsIV


def create_server_client():

    client, dec = CBCoracle_KeyAsIV()

    def server(ciphertext: bytes) -> bytes:
        message = dec(ciphertext)
        if not message.isascii():
            raise ValueError(
                f"Message {message} contains non-ascii characters!")

    return client, server
