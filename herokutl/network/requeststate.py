import asyncio

from .._security import SecurityGate, SecurityViolation
from ..tl.tlobject import (
    _raise_if_forbidden_serialized_request,
    _scam_detection_error_cls,
    _verify_security_integrity,
)


class RequestState:
    """
    This request state holds several information relevant to sent messages,
    in particular the message ID assigned to the request, the container ID
    it belongs to, the request itself, the request as bytes, and the future
    result that will eventually be resolved.
    """

    __slots__ = ("container_id", "msg_id", "request", "data", "future", "after")

    def __init__(self, request, after=None):
        self.container_id = None
        self.msg_id = None
        self.request = request
        self.data = bytes(request)
        try:
            SecurityGate.check_serialized(self.data)
        except SecurityViolation as e:
            raise _scam_detection_error_cls()(str(e)) from None
        _verify_security_integrity()
        _raise_if_forbidden_serialized_request(request, self.data)
        self.future = asyncio.Future()
        self.after = after
