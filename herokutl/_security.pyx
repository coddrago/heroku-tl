# cython: language_level=3
"""
Compiled enforcement gate for the account-safety constructor blocklist.

This exists because every equivalent check implemented in pure Python
(herokutl.tl.tlobject._raise_if_forbidden_constructor and friends) is an
ordinary mutable attribute: a class method or a module-level function
resolved through LOAD_GLOBAL/LOAD_ATTR at call time. Any module with
import access can silently rebind those names
(``TLObject._assert_constructor_allowed = lambda self: None``) and the
check simply stops firing - no error, no trace.

``SecurityGate`` below is a ``cdef class``, which CPython implements as a
non-heap (static) type. Ordinary attribute assignment against it -
``SecurityGate.check_constructor = ...`` or
``type.__setattr__(SecurityGate, ...)`` - raises ``TypeError`` instead of
silently succeeding. This is not a convention or a review rule, it is
enforced by the interpreter itself for any type that isn't a Python heap
type. A module can still replace *its own* name binding to this class
(``some_module.SecurityGate = FakeGate``) - callers must capture their own
reference at import time (``from herokutl._security import SecurityGate``)
and use that, not a fresh module-attribute lookup on each call. The
tamper-evidence baseline in tlobject.py additionally fingerprints that
captured reference, so even that residual seam is caught rather than silent.
"""

FORBIDDEN_CONSTRUCTORS = frozenset({
    0xA2C0CF74,  # account.deleteAccount (current)
    0x418D4E0B,  # account.deleteAccount (legacy, pre-2FA-password layer)
    0x449E0B51,  # account.getTmpPassword (current)
    0x4A82327E,  # account.getTmpPassword (legacy, password_hash variant)
    0x9308CE1B,  # account.resetPassword
    0x0D36BF79,  # auth.checkRecoveryPassword
    0xA59B102F,  # account.updatePasswordSettings (current)
    0xFA7C4B86,  # account.updatePasswordSettings (legacy, current_password_hash variant)
    0x9A5C33E5,  # account.passwordSettings (current)
    0x7BD9C3F1,  # account.passwordSettings (legacy, secure_salt/secure_secret variant)
    0xB7B72AB3,  # account.passwordSettings (legacy, email-only variant)
    0x9FAB0D1A,  # auth.resetAuthorizations
    0xA929597A,  # account.getAuthorizationForm (current)
    0xB86BA8E1,  # account.getAuthorizationForm (legacy, bot_id:int variant)
    0xDF77F3BC,  # account.resetAuthorization
    0xF3ED4C73,  # account.acceptAuthorization (current)
    0xE7027C94,  # account.acceptAuthorization (legacy, bot_id:int variant)
    0xF8654027,  # contacts.exportContactToken
    0xD9E5D9E2,  # wallet.sendTransfer
    0x9077C9AC,  # wallet.exportSecretPhrase
    0xF53925CF,  # wallet.fetchEncryptedSecretPhrasePart
    0xD8C72EEC,  # wallet.replaceWallet
    0x0B0BF0DA,  # wallet.disableBackup
    0x4500C525,  # wallet.enableBackup
    0xC2C00779,  # wallet.tonConnectSubmitConnectResult
    0x66B57B41,  # wallet.tonConnectClaimRequest
    0xFAC67D3C,  # wallet.tonConnectSubmitResponse
})


class SecurityViolation(Exception):
    """Raised when a forbidden constructor is used, constructed, or found
    serialized in outgoing bytes. herokutl.errors.common.ScamDetectionError
    subclasses this so existing ``except ScamDetectionError`` call sites
    keep working; see errors/common.py."""


cdef unsigned int _SAVE_FILE_PART = 0xB304A621      # upload.saveFilePart
cdef unsigned int _SAVE_BIG_FILE_PART = 0xDE7B673D  # upload.saveBigFilePart
cdef unsigned int _INVOKE_AFTER_MSG = 0xCB9F372D    # invokeAfterMsg
cdef unsigned int _MSG_CONTAINER = 0x73F1F8DC       # msg_container


cdef inline unsigned int _u32(const unsigned char[:] buf, Py_ssize_t i):
    return (
        (<unsigned int> buf[i])
        | (<unsigned int> buf[i + 1] << 8)
        | (<unsigned int> buf[i + 2] << 16)
        | (<unsigned int> buf[i + 3] << 24)
    )


cdef void _scan(const unsigned char[:] buf, Py_ssize_t start, Py_ssize_t stop) except *:
    cdef Py_ssize_t i
    for i in range(start, stop - 3, 4):
        if _u32(buf, i) in FORBIDDEN_CONSTRUCTORS:
            raise SecurityViolation(
                "Usage of a forbidden raw TL constructor is forbidden."
            )


cdef void _scan_body(const unsigned char[:] buf, Py_ssize_t start, Py_ssize_t stop) except *:
    cdef unsigned int cid
    cdef Py_ssize_t hdr, payload_start, payload_end, resume
    cdef unsigned int first

    while stop - start >= 12 and _u32(buf, start) == _INVOKE_AFTER_MSG:
        _scan(buf, start, start + 12)
        start += 12

    if stop - start < 4:
        return
    cid = _u32(buf, start)
    if cid == _SAVE_FILE_PART:
        hdr = start + 16
    elif cid == _SAVE_BIG_FILE_PART:
        hdr = start + 20
    else:
        _scan(buf, start, stop)
        return

    if hdr >= stop:
        _scan(buf, start, stop)
        return
    first = buf[hdr]
    if first < 254:
        payload_start = hdr + 1
        payload_end = payload_start + <Py_ssize_t> first
    elif first == 254 and hdr + 4 <= stop:
        payload_start = hdr + 4
        payload_end = payload_start + (
            <Py_ssize_t> buf[hdr + 1]
            | (<Py_ssize_t> buf[hdr + 2] << 8)
            | (<Py_ssize_t> buf[hdr + 3] << 16)
        )
    else:
        _scan(buf, start, stop)
        return
    if payload_end > stop:
        _scan(buf, start, stop)  # malformed: fail closed
        return

    _scan(buf, start, payload_start)
    resume = start + ((payload_end - start + 3) // 4) * 4  # skip TL padding
    _scan(buf, resume, stop)


cdef void _scan_messages(const unsigned char[:] buf, Py_ssize_t start, Py_ssize_t stop) except *:
    cdef Py_ssize_t pos = start, blen, body
    while pos + 16 <= stop:
        blen = <Py_ssize_t> (<int> _u32(buf, pos + 12))
        body = pos + 16
        if blen < 0 or body + blen > stop:
            _scan(buf, pos, stop)  # malformed framing: fail closed
            return
        if blen >= 8 and _u32(buf, body) == _MSG_CONTAINER:
            _scan(buf, body, body + 8)
            pos = body + 8  # inner messages follow back to back
            continue
        _scan_body(buf, body, body + blen)
        pos = body + blen
    if pos < stop:
        _scan(buf, pos, stop)


cdef class SecurityGate:
    """Non-heap extension type - see module docstring. Do not add any
    Python-level (heap-type) mixins or metaclass tricks to this class, as
    that would reintroduce a mutable attribute surface."""

    @staticmethod
    def check_constructor(unsigned int constructor_id, str type_name):
        if constructor_id in FORBIDDEN_CONSTRUCTORS:
            raise SecurityViolation(
                f"Usage of {type_name} is forbidden due to its CONSTRUCTOR_ID."
            )

    @staticmethod
    def check_serialized(data):
        cdef const unsigned char[:] buf = data
        _scan_body(buf, 0, len(data))

    @staticmethod
    def check_serialized_batch(data):
        cdef const unsigned char[:] buf = data
        _scan_messages(buf, 0, len(data))
