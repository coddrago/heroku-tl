import asyncio

from .connection import Connection, PacketCodec

SSL_PORT = 443


class HttpPacketCodec(PacketCodec):
    tag = None
    obfuscate_tag = None

    def encode_packet(self, data):
        return (
            "POST /api HTTP/1.1\r\n"
            "Host: {}:{}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Connection: keep-alive\r\n"
            "Keep-Alive: timeout=100000, max=10000000\r\n"
            "Content-Length: {}\r\n\r\n".format(
                self._conn._ip, self._conn._port, len(data)
            ).encode("ascii")
            + data
        )

    async def read_packet(self, reader):
        length = None
        header_size = 0
        for index in range(100):
            line = await reader.readline()
            if not line or not line.endswith(b"\r\n"):
                raise asyncio.IncompleteReadError(line, None)
            header_size += len(line)
            if header_size > 16 * 1024:
                raise BufferError("HTTP transport headers too large")
            if index == 0:
                status = line.split()
                if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status[1] != b"200":
                    raise BufferError("Invalid HTTP transport response status")
                continue
            if line == b"\r\n":
                if length is None:
                    raise BufferError("Missing HTTP transport content length")
                return await reader.readexactly(length)
            name, separator, value = line.partition(b":")
            if not separator:
                raise BufferError("Malformed HTTP transport header")
            if name.lower() == b"content-length":
                value = value.strip()
                if length is not None or not value.isdigit() or len(value) > 10:
                    raise BufferError("Invalid HTTP transport content length")
                length = int(value)
                self._check_packet_length(length)
            elif name.lower() == b"transfer-encoding":
                raise BufferError("Unsupported HTTP transport transfer encoding")
        raise BufferError("Too many HTTP transport headers")


class ConnectionHttp(Connection):
    packet_codec = HttpPacketCodec

    async def connect(self, timeout=None, ssl=None):
        await super().connect(timeout=timeout, ssl=self._port == SSL_PORT)
