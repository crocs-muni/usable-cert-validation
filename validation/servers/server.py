import ssl
import argparse
import asyncio


class Server:
    """A simple dummy TLS server with no functionality."""

    def __init__(self, key_path: str, cert_path: str):
        """Initialize a Server with its private key and certificate.

        Keyword arguments:
        key_path -- path to the server's private key
        cert_path -- path to the corresponding server certificate

        """
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self.context.load_cert_chain(cert_path, key_path)

    def handle_connection(reader, writer, third):
        pass

    def listen(self, addr: str, port: int):
        """Wait for a single connection, perform a handshake, then terminate.

        Keyword arguments:
        addr -- IP address to listen on
        port -- port to listen on

        """
        loop = asyncio.get_event_loop()
        coroutine = asyncio.start_server(self.handle_connection,
                                         addr,
                                         port,
                                         ssl=self.context,
                                         loop=loop)
        loop.run_until_complete(coroutine)
        loop.run_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host')
    parser.add_argument('--port')
    parser.add_argument('--key_file')
    parser.add_argument('--chain_file')
    args = parser.parse_args()

    server = Server(args.key_file, args.chain_file)
    server.listen(args.host, int(args.port))


if __name__ == "__main__":
    main()
