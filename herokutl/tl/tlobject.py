import base64
import json
import struct
from datetime import datetime, date, timedelta, timezone
import time
from ..errors import common

_ScamDetectionError = None

_EPOCH_NAIVE = datetime(*time.gmtime(0)[:6])
_EPOCH_NAIVE_LOCAL = datetime(*time.localtime(0)[:6])
_EPOCH = _EPOCH_NAIVE.replace(tzinfo=timezone.utc)


FORBIDDEN_CONSTRUCTORS = {
    0xA2C0CF74,  # account.DeleteAccount
    0x449E0B51,  # account.GetTmpPassword
    0x9308CE1B,  # account.ResetPassword
    0xD36BF79,  # auth.CheckRecoveryPassword
    0xA59B102F,  # account.UpdatePasswordSettings
    0x9A5C33E5,  # account.PasswordSettings
    0x9FAB0D1A,  # auth.ResetAuthorizations
    0xA929597A,  # account.GetAuthorizationForm
    0xE320C158,  # account.GetAuthorizations
    0xF8654027,  # contacts.ExportContactToken
}

FORBIDDEN_WEBAPP_IDS = [1985737506, 1559501630]

DUMMY_MESSAGE_KWARGS = {
    "message": base64.b64encode(base64.b64encode(bytes([109, 101, 111, 119]))).decode(),
    "reply_markup": None,
}

RESTRICT_IDS = [777000, 489000, 4245000]


def _get_forbid_constructors():
    return FORBIDDEN_CONSTRUCTORS


def _bind_scam_detection_error(error_cls):
    global _ScamDetectionError
    _ScamDetectionError = error_cls


def _scam_detection_error_cls():
    if _ScamDetectionError is None:
        return common.ScamDetectionError
    return _ScamDetectionError


def _raise_if_forbidden_constructor(cls):
    if cls.CONSTRUCTOR_ID in _get_forbid_constructors():
        raise _scam_detection_error_cls()(
            f"Usage of {cls.__name__} is forbidden due to its CONSTRUCTOR_ID."
        )


def _datetime_to_timestamp(dt):
    # If no timezone is specified, it is assumed to be in utc zone
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # We use .total_seconds() method instead of simply dt.timestamp(),
    # because on Windows the latter raises OSError on datetimes ~< datetime(1970,1,1)
    secs = int((dt - _EPOCH).total_seconds())
    # Make sure it's a valid signed 32 bit integer, as used by Telegram.
    # This does make very large dates wrap around, but it's the best we
    # can do with Telegram's limitations.
    return struct.unpack("i", struct.pack("I", secs & 0xFFFFFFFF))[0]


def _json_default(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    elif isinstance(value, datetime):
        return value.isoformat()
    else:
        return repr(value)


def _mask_phones_in_data(data):
    if isinstance(data, dict):
        new = {}
        for k, v in data.items():
            if k == "phone":
                new[k] = "phone?"
            else:
                new[k] = _mask_phones_in_data(v)
        return new
    if isinstance(data, list):
        return [_mask_phones_in_data(x) for x in data]
    if isinstance(data, tuple):
        return tuple(_mask_phones_in_data(x) for x in data)
    return data


class TLObject:
    CONSTRUCTOR_ID = None
    SUBCLASS_OF_ID = None

    def __new__(cls, *args, **kwargs):
        _raise_if_forbidden_constructor(cls)
        return super().__new__(cls)

    def __init__(self):
        self._assert_constructor_allowed()

        from .types import Message

        if self.CONSTRUCTOR_ID == Message.CONSTRUCTOR_ID and (
            _from_id := getattr(self, "from_id", None) or getattr(self, "peer_id", None)
        ):
            all_values = _from_id.to_dict().values()
            for i in RESTRICT_IDS:
                if i in all_values:
                    for k, v in DUMMY_MESSAGE_KWARGS.items():
                        setattr(self, k, v)
                    break

    def _check_peer(self, peer):
        from .functions.messages import RequestWebViewRequest

        if self.CONSTRUCTOR_ID == RequestWebViewRequest.CONSTRUCTOR_ID and any(
            v in FORBIDDEN_WEBAPP_IDS for v in peer.to_dict().values()
        ):
            raise _scam_detection_error_cls()(
                "⚠️ Tried to get WebApp authorization link for bot. "
            )

    @classmethod
    def _assert_constructor_allowed(cls):
        _raise_if_forbidden_constructor(cls)

    def _assert_no_forbidden_constructors(self):
        visited = set()

        def walk(value):
            value_id = id(value)
            if value_id in visited:
                return
            visited.add(value_id)

            if isinstance(value, TLObject):
                value._assert_constructor_allowed()
                for child in getattr(value, "__dict__", {}).values():
                    walk(child)
            elif isinstance(value, dict):
                for key, child in value.items():
                    walk(key)
                    walk(child)
            elif isinstance(value, (list, tuple, set, frozenset)):
                for child in value:
                    walk(child)

        walk(self)

    @staticmethod
    def pretty_format(obj, indent=None):
        """
        Pretty formats the given object as a string which is returned.
        If indent is None, a single line will be returned.
        """
        if indent is None:
            if isinstance(obj, TLObject):
                obj = obj.to_dict()

            if isinstance(obj, dict):
                return "{}({})".format(
                    obj.get("_", "dict"),
                    ", ".join(
                        "{}={}".format(
                            k, "phone?" if k == "phone" else TLObject.pretty_format(v)
                        )
                        for k, v in obj.items()
                        if k != "_"
                    ),
                )
            elif isinstance(obj, str) or isinstance(obj, bytes):

                try:
                    text = obj.decode() if isinstance(obj, bytes) else obj
                except Exception:
                    text = repr(obj)
                for i in RESTRICT_IDS:
                    text = text.replace(str(i), "<hidden-id>")
                return repr(text)
            elif hasattr(obj, "__iter__"):
                return "[{}]".format(", ".join(TLObject.pretty_format(x) for x in obj))
            else:
                if isinstance(obj, int):
                    if obj in RESTRICT_IDS or abs(obj) in RESTRICT_IDS:
                        return "<hidden-id>"
                return repr(obj)
        else:
            result = []
            if isinstance(obj, TLObject):
                obj = obj.to_dict()

            if isinstance(obj, dict):
                result.append(obj.get("_", "dict"))
                result.append("(")
                if obj:
                    result.append("\n")
                    indent += 1
                    for k, v in obj.items():
                        if k == "_":
                            continue
                        result.append("\t" * indent)
                        result.append(k)
                        result.append("=")
                        # Mask phone values when pretty-printing
                        if k == "phone":
                            result.append("phone?")
                        else:
                            result.append(TLObject.pretty_format(v, indent))
                        result.append(",\n")
                    result.pop()  # last ',\n'
                    indent -= 1
                    result.append("\n")
                    result.append("\t" * indent)
                result.append(")")

            elif isinstance(obj, str) or isinstance(obj, bytes):
                try:
                    text = obj.decode() if isinstance(obj, bytes) else obj
                except Exception:
                    text = repr(obj)
                for i in RESTRICT_IDS:
                    text = text.replace(str(i), "<hidden-id>")
                result.append(repr(text))

            elif hasattr(obj, "__iter__"):
                result.append("[\n")
                indent += 1
                for x in obj:
                    result.append("\t" * indent)
                    result.append(TLObject.pretty_format(x, indent))
                    result.append(",\n")
                indent -= 1
                result.append("\t" * indent)
                result.append("]")

            else:
                if isinstance(obj, int):
                    if obj in RESTRICT_IDS or abs(obj) in RESTRICT_IDS:
                        result.append("<hidden-id>")
                        return "".join(result)
                result.append(repr(obj))

            return "".join(result)

    @staticmethod
    def serialize_bytes(data):
        """Write bytes by using Telegram guidelines"""
        if not isinstance(data, bytes):
            if isinstance(data, str):
                data = data.encode("utf-8")
            else:
                raise TypeError("bytes or str expected, not {}".format(type(data)))

        r = []
        if len(data) < 254:
            padding = (len(data) + 1) % 4
            if padding != 0:
                padding = 4 - padding

            r.append(bytes([len(data)]))
            r.append(data)

        else:
            padding = len(data) % 4
            if padding != 0:
                padding = 4 - padding

            r.append(
                bytes(
                    [
                        254,
                        len(data) % 256,
                        (len(data) >> 8) % 256,
                        (len(data) >> 16) % 256,
                    ]
                )
            )
            r.append(data)

        r.append(bytes(padding))
        return b"".join(r)

    @staticmethod
    def serialize_datetime(dt):
        if not dt and not isinstance(dt, timedelta):
            return b"\0\0\0\0"

        if isinstance(dt, datetime):
            dt = _datetime_to_timestamp(dt)
        elif isinstance(dt, date):
            dt = _datetime_to_timestamp(datetime(dt.year, dt.month, dt.day))
        elif isinstance(dt, float):
            dt = int(dt)
        elif isinstance(dt, timedelta):
            # Timezones are tricky. datetime.utcnow() + ... timestamp() works
            dt = _datetime_to_timestamp(datetime.utcnow() + dt)

        if isinstance(dt, int):
            return struct.pack("<i", dt)

        raise TypeError('Cannot interpret "{}" as a date.'.format(dt))

    def __eq__(self, o):
        return isinstance(o, type(self)) and self.to_dict() == o.to_dict()

    def __ne__(self, o):
        return not isinstance(o, type(self)) or self.to_dict() != o.to_dict()

    def __str__(self):
        return TLObject.pretty_format(self)

    def stringify(self):
        return TLObject.pretty_format(self, indent=0)

    def to_dict(self):
        raise NotImplementedError

    def to_json(self, fp=None, default=_json_default, **kwargs):
        """
        Represent the current `TLObject` as JSON.

        If ``fp`` is given, the JSON will be dumped to said
        file pointer, otherwise a JSON string will be returned.

        Note that bytes and datetimes cannot be represented
        in JSON, so if those are found, they will be base64
        encoded and ISO-formatted, respectively, by default.
        """
        d = self.to_dict()
        try:
            d = _mask_phones_in_data(d)
        except Exception:
            pass
        if fp:
            return json.dump(d, fp, default=default, **kwargs)
        else:
            return json.dumps(d, default=default, **kwargs)

    def __bytes__(self):
        try:
            self._assert_no_forbidden_constructors()
            return self._bytes()
        except AttributeError:
            # If a type is wrong (e.g. expected `TLObject` but `int` was
            # provided) it will try to access `._bytes()`, which will fail
            # with `AttributeError`. This occurs in fact because the type
            # was wrong, so raise the correct error type.
            raise TypeError("a TLObject was expected but found something else")

    # Custom objects will call `(...)._bytes()` and not `bytes(...)` so that
    # if the wrong type is used (e.g. `int`) we won't try allocating a huge
    # amount of data, which would cause a `MemoryError`.
    def _bytes(self):
        raise NotImplementedError

    @classmethod
    def from_reader(cls, reader):
        raise NotImplementedError


class TLRequest(TLObject):
    """
    Represents a content-related `TLObject` (a request that can be sent).
    """

    @staticmethod
    def read_result(reader):
        return reader.tgread_object()

    async def resolve(self, client, utils):
        pass
