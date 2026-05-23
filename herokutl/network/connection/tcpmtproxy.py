import asyncio
import base64
import collections
import hashlib
import hmac
import os
import re
import time

from .connection import ObfuscatedConnection
from .tcpabridged import AbridgedPacketCodec
from .tcpintermediate import IntermediatePacketCodec, RandomizedIntermediatePacketCodec

from ...crypto import AESModeCTR

MTProxySecret = collections.namedtuple("MTProxySecret", ("secret", "fake_tls_domain"))


def _hmac_sha256(key, msg):
    return hmac.new(key=key, msg=msg, digestmod=hashlib.sha256).digest()


class MTProxyFakeTLS:
    _client_hello_fields = (
        ("content_type", b"\x16"),
        ("version", b"\x03\x01"),
        ("len", b"\x02\x00"),
        ("handshake_type", b"\x01"),
        ("handshake_len", b"\x00\x01\xfc"),
        ("handshake_version", b"\x03\x03"),
        ("random", b"\x00" * 32),
        ("session_id_len", b"\x20"),
        ("session_id", b"\x00" * 32),
        ("cipher_suites_len", b"\x00\x20"),
        (
            "cipher_suites",
            b"\xfa\xfa\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
            b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35",
        ),
        ("compression_methods_len", b"\x01"),
        ("compression_methods", b"\x00"),
        ("extensions_len", b"\x01\x93"),
        ("ext_reserved_1", b"\x4a\x4a\x00\x00"),
        ("ext_server_name_type", b"\x00\x00"),
        ("ext_server_name_len", b"\x00\x00"),
        ("ext_server_name_indication_list_len", b"\x00\x00"),
        ("ext_server_name_indication_type", b"\x00"),
        ("ext_server_name_indication_len", b"\x00\x00"),
        ("ext_server_name_indication", b"\x00"),
        ("ext_extended_master_secret", b"\x00\x17\x00\x00"),
        ("ext_renegotiation_info", b"\xff\x01\x00\x01\x00"),
        (
            "ext_supported_groups",
            b"\x00\x0a\x00\x0a\x00\x08\xba\xba\x00\x1d\x00\x17\x00\x18",
        ),
        ("ext_ec_point_formats", b"\x00\x0b\x00\x02\x01\x00"),
        ("ext_session_ticket", b"\x00\x23\x00\x00"),
        (
            "ext_alpn",
            b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31",
        ),
        ("ext_status_request", b"\x00\x05\x00\x05\x01\x00\x00\x00\x00"),
        (
            "ext_signature_algorithms",
            b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04"
            b"\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01",
        ),
        ("ext_signature_cert_timestamp", b"\x00\x12\x00\x00"),
        ("ext_key_share_type", b"\x00\x33"),
        ("ext_key_share_len", b"\x00\x2b"),
        ("ext_key_share_client_key_len", b"\x00\x29"),
        ("ext_key_share_reserved", b"\xba\xba\x00\x01\x00"),
        ("ext_key_share_group", b"\x00\x1d"),
        ("ext_key_share_exchange_len", b"\x00\x20"),
        ("ext_key_share_exchange", b"\x00" * 32),
        ("ext_psk_key_exchange_modes", b"\x00\x2d\x00\x02\x01\x01"),
        (
            "ext_supported_tls_versions",
            b"\x00\x2b\x00\x0b\x0a\x9a\x9a\x03\x04\x03\x03\x03\x02\x03\x01",
        ),
        ("ext_compress_cert", b"\x00\x1b\x00\x03\x02\x00\x02"),
        ("ext_reserved_2", b"\x1a\x1a\x00\x01\x00"),
        ("ext_padding_type", b"\x00\x15"),
        ("ext_padding_len", b"\x00\x00"),
        ("ext_padding", b""),
    )

    def __init__(self, secret, domain):
        self.secret = secret
        self.domain = domain
        self._client_hello = collections.OrderedDict(
            (key, value) for key, value in self._client_hello_fields
        )
        self._packet = None

    def _set(self, key, value):
        if isinstance(value, int):
            value = value.to_bytes(len(self._client_hello[key]), "big")
        self._client_hello[key] = value
        self._packet = None

    def _packet_bytes(self):
        if self._packet is None:
            self._packet = b"".join(self._client_hello.values())
        return self._packet

    def _set_domain(self):
        domain_len = len(self.domain)
        self._set("ext_server_name_len", 2 + 1 + 2 + domain_len)
        self._set("ext_server_name_indication_list_len", 1 + 2 + domain_len)
        self._set("ext_server_name_indication_len", domain_len)
        self._set("ext_server_name_indication", self.domain)

    def _fix_padding(self):
        self._set("ext_padding", b"")
        padding_len = 517 - len(self._packet_bytes())
        if padding_len < 0:
            raise ValueError("MTProxy Fake-TLS domain is too long")
        self._set("ext_padding_len", padding_len)
        self._set("ext_padding", b"\x00" * padding_len)

    def build_client_hello(self):
        self._set("session_id", os.urandom(32))
        self._set_domain()
        self._set("ext_key_share_exchange", os.urandom(32))
        self._fix_padding()
        self._set("random", b"\x00" * 32)

        digest = _hmac_sha256(self.secret, self._packet_bytes())
        current_time = int(time.time()).to_bytes(4, "little")
        xored_time = bytes(current_time[i] ^ digest[28 + i] for i in range(4))
        self._set("random", digest[:28] + xored_time)
        return self._packet_bytes()

    def verify_server_hello(self, server_hello):
        if len(server_hello) < 133:
            return False
        if not server_hello.startswith(b"\x16\x03\x03"):
            return False
        if server_hello[127:136] != b"\x14\x03\x03\x00\x01\x01\x17\x03\x03":
            return False
        if server_hello[44:76] != self._client_hello["session_id"]:
            return False

        client_digest = self._client_hello["random"]
        server_digest = server_hello[11:43]
        server_hello = server_hello[:11] + (b"\x00" * 32) + server_hello[43:]
        return server_digest == _hmac_sha256(self.secret, client_digest + server_hello)


class FakeTLSStreamReader:
    def __init__(self, upstream):
        self.upstream = upstream
        self.buf = bytearray()

    async def _read_record(self):
        tls_rec_type = await self.upstream.readexactly(1)
        if tls_rec_type not in (b"\x14", b"\x17"):
            raise ConnectionError("Bad Fake-TLS record type")

        version = await self.upstream.readexactly(2)
        if version != b"\x03\x03":
            raise ConnectionError("Bad Fake-TLS record version")

        data_len = int.from_bytes(await self.upstream.readexactly(2), "big")
        return tls_rec_type, await self.upstream.readexactly(data_len)

    async def read(self, n=-1, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf if n < 0 else self.buf[:n]
            self.buf = bytearray() if n < 0 else self.buf[n:]
            return bytes(data)

        if n == 0:
            return b""

        tls_rec_type, data = await self._read_record()
        if tls_rec_type == b"\x14":
            return await self.read(n, ignore_buf=ignore_buf)

        if n > -1 and len(data) > n and not ignore_buf:
            self.buf += data[n:]
            data = data[:n]
        return data

    async def readexactly(self, n):
        while len(self.buf) < n:
            self.buf += await self.read(ignore_buf=True)
        data = self.buf[:n]
        self.buf = self.buf[n:]
        return bytes(data)

    async def read_server_hello(self):
        server_hello = await self.upstream.readexactly(138)
        data_len = int.from_bytes(server_hello[-2:], "big")
        return server_hello + await self.upstream.readexactly(data_len)

    async def _wait_for_data(self, func_name):
        wait_for_data = getattr(self.upstream, "_wait_for_data", None)
        if wait_for_data is None:
            while not self.buf and not self.at_eof():
                await asyncio.sleep(0.05)
            return
        await wait_for_data(func_name)

    def at_eof(self):
        return not self.buf and self.upstream.at_eof()

    def exception(self):
        return self.upstream.exception()


class FakeTLSStreamWriter:
    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data):
        max_chunk_size = 16384
        for start in range(0, len(data), max_chunk_size):
            chunk = data[start : start + max_chunk_size]
            self.upstream.write(b"\x17\x03\x03" + len(chunk).to_bytes(2, "big") + chunk)

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def write_eof(self):
        return self.upstream.write_eof()

    def abort(self):
        return self.upstream.transport.abort()

    def get_extra_info(self, name, default=None):
        return self.upstream.get_extra_info(name, default)

    def is_closing(self):
        return self.upstream.is_closing()

    async def wait_closed(self):
        return await self.upstream.wait_closed()

    @property
    def transport(self):
        return self.upstream.transport


class MTProxyIO:
    """
    It's very similar to tcpobfuscated.ObfuscatedIO, but the way
    encryption keys, protocol tag and dc_id are encoded is different.
    """

    header = None

    def __init__(self, connection):
        self._reader = connection._reader
        self._writer = connection._writer

        self.header, self._encrypt, self._decrypt = self.init_header(
            connection._secret, connection._dc_id, connection.packet_codec
        )

    @staticmethod
    def init_header(secret, dc_id, packet_codec):
        # Validate
        is_dd = (len(secret) == 17) and (secret[0] == 0xDD)
        is_rand_codec = issubclass(packet_codec, RandomizedIntermediatePacketCodec)
        if is_dd and not is_rand_codec:
            raise ValueError("Only RandomizedIntermediate can be used with dd-secrets")
        is_ee = (len(secret) >= 17) and (secret[0] == 0xEE)
        if is_ee:
            raise ValueError(
                "Fake-TLS MTProxy secrets must be handled before init_header"
            )
        secret = secret[1:] if is_dd else secret
        if len(secret) != 16:
            raise ValueError(
                "MTProxy secret must be a hex-string representing 16 bytes"
            )

        # Obfuscated messages secrets cannot start with any of these
        keywords = (b"PVrG", b"GET ", b"POST", b"\xee\xee\xee\xee")
        while True:
            random = os.urandom(64)
            if (
                random[0] != 0xEF
                and random[:4] not in keywords
                and random[4:8] != b"\0\0\0\0"
            ):
                break

        random = bytearray(random)
        random_reversed = random[55:7:-1]  # Reversed (8, len=48)

        # Encryption has "continuous buffer" enabled
        encrypt_key = hashlib.sha256(bytes(random[8:40]) + secret).digest()
        encrypt_iv = bytes(random[40:56])
        decrypt_key = hashlib.sha256(bytes(random_reversed[:32]) + secret).digest()
        decrypt_iv = bytes(random_reversed[32:48])

        encryptor = AESModeCTR(encrypt_key, encrypt_iv)
        decryptor = AESModeCTR(decrypt_key, decrypt_iv)

        random[56:60] = packet_codec.obfuscate_tag

        dc_id_bytes = dc_id.to_bytes(2, "little", signed=True)
        random = random[:60] + dc_id_bytes + random[62:]
        random[56:64] = encryptor.encrypt(bytes(random))[56:64]
        return (random, encryptor, decryptor)

    async def readexactly(self, n):
        return self._decrypt.encrypt(await self._reader.readexactly(n))

    def write(self, data):
        self._writer.write(self._encrypt.encrypt(data))


class TcpMTProxy(ObfuscatedConnection):
    """
    Connector which allows user to connect to the Telegram via proxy servers
    commonly known as MTProxy.
    Implemented very ugly due to the leaky abstractions in Telethon networking
    classes that should be refactored later (TODO).

    .. warning::

        The support for TcpMTProxy classes is **EXPERIMENTAL** and prone to
        be changed. You shouldn't be using this class yet.
    """

    packet_codec = None
    obfuscated_io = MTProxyIO

    # noinspection PyUnusedLocal
    def __init__(self, ip, port, dc_id, *, loggers, proxy=None, local_addr=None):
        # connect to proxy's host and port instead of telegram's ones
        proxy_host, proxy_port = self.address_info(proxy)
        parsed_secret = self.normalize_secret(proxy[2])
        self._secret = parsed_secret.secret
        self._fake_tls = (
            MTProxyFakeTLS(parsed_secret.secret, parsed_secret.fake_tls_domain)
            if parsed_secret.fake_tls_domain
            else None
        )
        super().__init__(
            proxy_host, proxy_port, dc_id, loggers=loggers, local_addr=local_addr
        )

    async def _connect(self, timeout=None, ssl=None):
        if self._fake_tls:
            await self._connect_fake_tls(timeout=timeout, ssl=ssl)
        else:
            await super()._connect(timeout=timeout, ssl=ssl)

        # Wait for EOF for 2 seconds (or if _wait_for_data's definition
        # is missing or different, just sleep for 2 seconds). This way
        # we give the proxy a chance to close the connection if the current
        # codec (which the proxy detects with the data we sent) cannot
        # be used for this proxy. This is a work around for #1134.
        # TODO Sleeping for N seconds may not be the best solution
        # TODO This fix could be welcome for HTTP proxies as well
        try:
            await asyncio.wait_for(self._reader._wait_for_data("proxy"), 2)
        except asyncio.TimeoutError:
            pass
        except Exception:
            await asyncio.sleep(2)

        if self._reader.at_eof():
            await self.disconnect()
            raise ConnectionError(
                "Proxy closed the connection after sending initial payload"
            )

    async def _connect_fake_tls(self, timeout=None, ssl=None):
        if self._local_addr is not None:
            if isinstance(self._local_addr, tuple) and len(self._local_addr) == 2:
                local_addr = self._local_addr
            elif isinstance(self._local_addr, str):
                local_addr = (self._local_addr, 0)
            else:
                raise ValueError(
                    "Unknown local address format: {}".format(self._local_addr)
                )
        else:
            local_addr = None

        if not self._proxy:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self._ip, port=self._port, ssl=ssl, local_addr=local_addr
                ),
                timeout=timeout,
            )
        else:
            sock = await self._proxy_connect(timeout=timeout, local_addr=local_addr)
            if ssl:
                sock = self._wrap_socket_ssl(sock)
            self._reader, self._writer = await asyncio.open_connection(sock=sock)

        self._writer.write(self._fake_tls.build_client_hello())
        await self._writer.drain()

        fake_tls_reader = FakeTLSStreamReader(self._reader)
        server_hello = await asyncio.wait_for(
            fake_tls_reader.read_server_hello(), timeout=timeout
        )
        if not self._fake_tls.verify_server_hello(server_hello):
            raise ConnectionError("Fake-TLS MTProxy server hello verification failed")

        self._reader = fake_tls_reader
        self._writer = FakeTLSStreamWriter(self._writer)
        self._codec = self.packet_codec(self)
        self._init_conn()
        await self._writer.drain()

    @staticmethod
    def address_info(proxy_info):
        if proxy_info is None:
            raise ValueError("No proxy info specified for MTProxy connection")
        return proxy_info[:2]

    @staticmethod
    def normalize_secret(secret):
        if isinstance(secret, bytes):
            secret_bytes = secret
        else:
            secret = secret.strip()
            try:
                secret_bytes = bytes.fromhex(secret)
            except ValueError:
                secret = re.sub(r"[^a-zA-Z0-9_\-+/=]+", "", secret)
                secret += "=" * (-len(secret) % 4)
                secret_bytes = base64.urlsafe_b64decode(secret.encode())

        if len(secret_bytes) == 16:
            return MTProxySecret(secret_bytes, None)

        if len(secret_bytes) == 17 and secret_bytes[0] == 0xDD:
            return MTProxySecret(secret_bytes, None)

        if len(secret_bytes) > 17 and secret_bytes[0] == 0xEE:
            secret, domain = secret_bytes[1:17], secret_bytes[17:]
            if not domain:
                raise ValueError("MTProxy Fake-TLS secret must include a domain")
            return MTProxySecret(secret, domain)

        raise ValueError(
            "MTProxy secret must be 16 bytes, dd + 16 bytes, "
            "or ee + 16-byte-secret + domain-hex"
        )


class ConnectionTcpMTProxyAbridged(TcpMTProxy):
    """
    Connect to proxy using abridged protocol
    """

    packet_codec = AbridgedPacketCodec


class ConnectionTcpMTProxyIntermediate(TcpMTProxy):
    """
    Connect to proxy using intermediate protocol
    """

    packet_codec = IntermediatePacketCodec


class ConnectionTcpMTProxyRandomizedIntermediate(TcpMTProxy):
    """
    Connect to proxy using randomized intermediate protocol (dd-secrets)
    """

    packet_codec = RandomizedIntermediatePacketCodec
