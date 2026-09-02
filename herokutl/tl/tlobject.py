import base64
import json
import logging
import struct
from datetime import datetime, date, timedelta, timezone
import time
from ..errors import common
from .._security import SecurityGate, SecurityViolation, FORBIDDEN_CONSTRUCTORS

_ScamDetectionError = None

_EPOCH_NAIVE = datetime(*time.gmtime(0)[:6])
_EPOCH_NAIVE_LOCAL = datetime(*time.localtime(0)[:6])
_EPOCH = _EPOCH_NAIVE.replace(tzinfo=timezone.utc)



_VECTOR_CONSTRUCTOR_ID = 0x1CB5C415
_USERS_GET_USERS_CONSTRUCTOR_ID = 0x0D91A548
_INPUT_USER_SELF_CONSTRUCTOR_ID = 0xF7C1B13F
_GENERATED_FUNCTIONS_MODULE_PREFIX = "herokutl.tl.functions"
_MASKED_PHONE = "phone?"
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
    try:
        SecurityGate.check_constructor(cls.CONSTRUCTOR_ID or 0, cls.__name__)
    except SecurityViolation as e:
        raise _scam_detection_error_cls()(str(e)) from None


def _read_uint(data, offset):
    if offset < 0 or len(data) - offset < 4:
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _serialized_get_users_targets_self(data, offset):
    offset += 4
    if _read_uint(data, offset) != _VECTOR_CONSTRUCTOR_ID:
        return False

    count = _read_uint(data, offset + 4)
    if count is None or count < 0 or count > 10000:
        return False

    offset += 8
    for _ in range(count):
        constructor_id = _read_uint(data, offset)
        if constructor_id is None:
            return False
        if constructor_id == _INPUT_USER_SELF_CONSTRUCTOR_ID:
            return True

        # inputUser#f21158c6 user_id:long access_hash:long
        if constructor_id == 0xF21158C6:
            offset += 20
        # inputUserFromMessage#1da448e2 peer:InputPeer msg_id:int user_id:long.
        # The peer is nested and variable-sized, so keep scanning the rest of the
        # serialized request instead of trying to partially deserialize it here.
        else:
            return any(
                _read_uint(data, i) == _INPUT_USER_SELF_CONSTRUCTOR_ID
                for i in range(offset + 4, len(data) - 3, 4)
            )

    return False


def _serialized_request_gets_self_user(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return False

    data = bytes(data)
    return any(
        _read_uint(data, offset) == _USERS_GET_USERS_CONSTRUCTOR_ID
        and _serialized_get_users_targets_self(data, offset)
        for offset in range(0, len(data) - 3, 4)
    )


def _is_custom_result_reader(request):
    if not isinstance(request, TLRequest):
        return False

    if "read_result" in getattr(request, "__dict__", {}):
        return True

    for cls in request.__class__.__mro__:
        if "read_result" in getattr(cls, "__dict__", {}):
            return cls is not TLRequest

    return False


def _is_generated_tl_function_request(request):
    module = getattr(request.__class__, "__module__", "")
    return module.startswith(_GENERATED_FUNCTIONS_MODULE_PREFIX)


def _is_raw_or_external_serialized_request(request):
    return not _is_generated_tl_function_request(request)


def _raise_if_forbidden_serialized_request(request, data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return

    data = bytes(data)
    try:
        SecurityGate.check_serialized(data)
    except SecurityViolation as e:
        raise _scam_detection_error_cls()(str(e)) from None

    if _serialized_request_gets_self_user(
        data
    ) and _is_raw_or_external_serialized_request(request):
        raise _scam_detection_error_cls()(
            "Raw users.getUsers(InputUserSelf) requests are forbidden."
        )

_SECURITY_BASELINE = None
_TAMPER_ALERTED = False
_security_logger = logging.getLogger(__name__)


def _snapshot_security_state():
    return {
        "TLObject.__new__": vars(TLObject).get("__new__"),
        "TLObject.__init__": vars(TLObject).get("__init__"),
        "TLObject._assert_constructor_allowed": vars(TLObject).get(
            "_assert_constructor_allowed"
        ),
        "TLObject._assert_no_forbidden_constructors": vars(TLObject).get(
            "_assert_no_forbidden_constructors"
        ),
        "TLObject.__bytes__": vars(TLObject).get("__bytes__"),
        "_raise_if_forbidden_constructor": globals().get(
            "_raise_if_forbidden_constructor"
        ),
        "_raise_if_forbidden_serialized_request": globals().get(
            "_raise_if_forbidden_serialized_request"
        ),
    }


def _capture_security_baseline():
    global _SECURITY_BASELINE
    if _SECURITY_BASELINE is None:
        _SECURITY_BASELINE = _snapshot_security_state()


def _verify_security_integrity():
    global _TAMPER_ALERTED
    if _SECURITY_BASELINE is None or _TAMPER_ALERTED:
        return
    current = _snapshot_security_state()
    tampered = [
        name
        for name, original in _SECURITY_BASELINE.items()
        if current.get(name) is not original
    ]
    if tampered:
        _TAMPER_ALERTED = True
        _security_logger.critical(
            "Security enforcement tampering detected in herokutl.tl.tlobject: "
            + ", ".join(tampered)
            + ". A loaded module has rebound one or more of the account "
            "safety checks."
        )


def _mask_phone_attributes(data):
    visited = set()

    def walk(value):
        value_id = id(value)
        if value_id in visited:
            return
        visited.add(value_id)

        if isinstance(value, TLObject):
            for key, child in getattr(value, "__dict__", {}).items():
                if key == "phone":
                    try:
                        setattr(value, key, _MASKED_PHONE)
                    except Exception:
                        pass
                else:
                    walk(child)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key == "phone":
                    value[key] = _MASKED_PHONE
                else:
                    walk(child)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for child in value:
                walk(child)

    walk(data)
    return data


def _sanitize_sensitive_result(request, result):
    if isinstance(result, memoryview):
        return b""
    if isinstance(result, bytearray):
        return bytearray()
    if isinstance(result, bytes):
        return b""
    return _mask_phone_attributes(result)


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
        try:
            SecurityGate.check_constructor(cls.CONSTRUCTOR_ID or 0, cls.__name__)
        except SecurityViolation as e:
            raise _scam_detection_error_cls()(str(e)) from None
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
        try:
            SecurityGate.check_constructor(cls.CONSTRUCTOR_ID or 0, cls.__name__)
        except SecurityViolation as e:
            raise _scam_detection_error_cls()(str(e)) from None

    def _assert_no_forbidden_constructors(self):
        _verify_security_integrity()
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

_capture_security_baseline()


class TLRequest(TLObject):
    """
    Represents a content-related `TLObject` (a request that can be sent).
    """

    @staticmethod
    def read_result(reader):
        return reader.tgread_object()

    async def resolve(self, client, utils):
        pass
