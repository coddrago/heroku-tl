try:
    from isal import igzip as gzip
except ImportError:
    import gzip
import struct
import zlib

from .. import TLObject
from ...errors import SecurityError


class GzipPacked(TLObject):
    CONSTRUCTOR_ID = 0x3072CFA1
    MAX_UNPACKED_SIZE = 16 * 1024 * 1024

    @classmethod
    def _decompress(cls, data):
        unpacker = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            result = unpacker.decompress(data, cls.MAX_UNPACKED_SIZE + 1)
        except zlib.error as e:
            raise SecurityError("Invalid gzip payload") from e
        if len(result) > cls.MAX_UNPACKED_SIZE or unpacker.unconsumed_tail:
            raise SecurityError("Gzip payload exceeds the unpacked size limit")
        if not unpacker.eof or unpacker.unused_data:
            raise SecurityError("Invalid gzip payload boundary")
        return result

    def __init__(self, data):
        self.data = data

    @staticmethod
    def gzip_if_smaller(content_related, data):
        """Calls bytes(request), and based on a certain threshold,
        optionally gzips the resulting data. If the gzipped data is
        smaller than the original byte array, this is returned instead.

        Note that this only applies to content related requests.
        """
        if content_related and len(data) > 512:
            gzipped = bytes(GzipPacked(data))
            return gzipped if len(gzipped) < len(data) else data
        else:
            return data

    def __bytes__(self):
        return struct.pack("<I", GzipPacked.CONSTRUCTOR_ID) + TLObject.serialize_bytes(
            gzip.compress(self.data)
        )

    @staticmethod
    def read(reader):
        constructor = reader.read_int(signed=False)
        if constructor != GzipPacked.CONSTRUCTOR_ID:
            raise SecurityError("Invalid gzip constructor")
        return GzipPacked._decompress(reader.tgread_bytes())

    @classmethod
    def from_reader(cls, reader):
        return cls(cls._decompress(reader.tgread_bytes()))

    def to_dict(self):
        return {"_": "GzipPacked", "data": self.data}
