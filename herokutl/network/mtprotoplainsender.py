"""
This module contains the class used to communicate with Telegram's servers
in plain text, when no authorization key has been created yet.
"""

import struct

from .mtprotostate import MTProtoState
from ..errors import InvalidBufferError, SecurityError
from ..extensions import BinaryReader


class MTProtoPlainSender:
    """
    MTProto Mobile Protocol plain sender
    (https://core.telegram.org/mtproto/description#unencrypted-messages)
    """

    def __init__(self, connection, *, loggers):
        """
        Initializes the MTProto plain sender.

        :param connection: the Connection to be used.
        """
        self._state = MTProtoState(auth_key=None, loggers=loggers)
        self._connection = connection

    async def send(self, request):
        """
        Sends and receives the result for the given request.
        """
        body = bytes(request)
        msg_id = self._state._get_new_msg_id()
        await self._connection.send(struct.pack("<qqi", 0, msg_id, len(body)) + body)

        body = await self._connection.recv()
        if len(body) < 24:
            raise InvalidBufferError(body)

        with BinaryReader(body) as reader:
            auth_key_id = reader.read_long()
            if auth_key_id != 0:
                raise SecurityError("Invalid plain auth_key_id")

            msg_id = reader.read_long()
            if msg_id % 2 != 1:
                raise SecurityError("Invalid plain msg_id")
            # ^ We should make sure that the read ``msg_id`` is greater
            # than our own ``msg_id``. However, under some circumstances
            # (bad system clock/working behind proxies) this seems to not
            # be the case, which would cause endless assertion errors.

            length = reader.read_int()
            if length < 4 or length % 4 or length != len(body) - 20:
                raise SecurityError("Invalid plain message length")
            result = reader.tgread_object()
            if reader.tell_position() != len(body):
                raise SecurityError("Invalid plain message boundary")
            return result
