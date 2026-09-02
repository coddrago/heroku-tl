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
    0xE320C158,  # account.getAuthorizations
    0xF8654027,  # contacts.exportContactToken
})


class SecurityViolation(Exception):
    """Raised when a forbidden constructor is used, constructed, or found
    serialized in outgoing bytes. herokutl.errors.common.ScamDetectionError
    subclasses this so existing ``except ScamDetectionError`` call sites
    keep working; see errors/common.py."""


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
        cdef Py_ssize_t i, n
        cdef unsigned int cid
        cdef const unsigned char[:] buf = data
        n = len(data)
        for i in range(0, n - 3, 4):
            cid = (
                (<unsigned int> buf[i])
                | (<unsigned int> buf[i + 1] << 8)
                | (<unsigned int> buf[i + 2] << 16)
                | (<unsigned int> buf[i + 3] << 24)
            )
            if cid in FORBIDDEN_CONSTRUCTORS:
                raise SecurityViolation(
                    "Usage of a forbidden raw TL constructor is forbidden."
                )
