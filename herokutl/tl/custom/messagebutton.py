from .. import types, functions
from ... import password as pwd_mod
from ...errors import BotResponseTimeoutError

try:
    import webbrowser
except ModuleNotFoundError:
    pass
import sys
import os


class MessageButton:
    """
    .. note::

        `Message.buttons <telethon.tl.custom.message.Message.buttons>`
        are instances of this type. If you want to **define** a reply
        markup for e.g. sending messages, refer to `Button
        <telethon.tl.custom.button.Button>` instead.

    Custom class that encapsulates a message button providing
    an abstraction to easily access some commonly needed features
    (such as clicking the button itself).

    Attributes:

        button (:tl:`KeyboardButton`, :tl:`KeyboardInlineButton`):
            The original :tl:`KeyboardButton` object.
    """

    def __init__(self, client, original, chat, bot, msg_id):
        self.button = original
        self._bot = bot
        self._chat = chat
        self._msg_id = msg_id
        self._client = client

    @property
    def client(self):
        """
        Returns the `telethon.client.telegramclient.TelegramClient`
        instance that created this instance.
        """
        return self._client

    @property
    def text(self):
        """The text string of the button."""
        return self.button.text

    @property
    def data(self):
        """The `bytes` data for :tl:`InlineButtonTypeCallback` objects."""
        if isinstance(self.button.type, types.InlineButtonTypeCallback):
            return self.button.type.data

    @property
    def inline_query(self):
        """The query `str` for :tl:`InlineButtonTypeSwitchInline` objects."""
        if isinstance(self.button.type, types.InlineButtonTypeSwitchInline):
            return self.button.type.query

    @property
    def url(self):
        """The url `str` for :tl:`InlineButtonTypeUrl` objects."""
        if isinstance(self.button.type, types.InlineButtonTypeUrl):
            return self.button.type.url

    async def click(
        self, share_phone=None, share_geo=None, *, password=None, open_url=None
    ):
        """
        Emulates the behaviour of clicking this button.

        If it's a normal :tl:`ButtonTypeDefault` with text, a message will be
        sent, and the sent `Message <telethon.tl.custom.message.Message>` returned.

        If it's an inline :tl:`InlineButtonTypeCallback` with text and data,
        it will be "clicked" and the :tl:`BotCallbackAnswer` returned.

        If it's an inline :tl:`InlineButtonTypeSwitchInline` button, the
        :tl:`StartBotRequest` will be invoked and the resulting updates
        returned.

        If it's a :tl:`InlineButtonTypeUrl`, the ``URL`` of the button will
        be returned. If you pass ``open_url=True`` the URL of the button will
        be passed to ``webbrowser.open`` and return `True` on success.

        If it's a :tl:`ButtonTypeRequestPhone`, you must indicate that you
        want to ``share_phone=True`` in order to share it. Sharing it is not a
        default because it is a privacy concern and could happen accidentally.

        You may also use ``share_phone=phone`` to share a specific number, in
        which case either `str` or :tl:`InputMediaContact` should be used.

        If it's a :tl:`ButtonTypeRequestGeoLocation`, you must pass a
        tuple in ``share_geo=(longitude, latitude)``. Note that Telegram seems
        to have some heuristics to determine impossible locations, so changing
        this value a lot quickly may not work as expected. You may also pass a
        :tl:`InputGeoPoint` if you find the order confusing.
        """
        if isinstance(self.button.type, types.ButtonTypeDefault):
            return await self._client.send_message(
                self._chat, self.button.text, parse_mode=None
            )
        elif isinstance(self.button.type, types.InlineButtonTypeCallback):
            if password is not None:
                pwd = await self._client(functions.account.GetPasswordRequest())
                password = pwd_mod.compute_check(pwd, password)

            req = functions.messages.GetBotCallbackAnswerRequest(
                peer=self._chat,
                msg_id=self._msg_id,
                data=self.button.type.data,
                password=password,
            )
            try:
                return await self._client(req)
            except BotResponseTimeoutError:
                return None
        elif isinstance(self.button.type, types.InlineButtonTypeSwitchInline):
            return await self._client(
                functions.messages.StartBotRequest(
                    bot=self._bot, peer=self._chat, start_param=self.button.type.query
                )
            )
        elif isinstance(self.button.type, types.InlineButtonTypeUrl):
            if open_url:
                if "webbrowser" in sys.modules:
                    return webbrowser.open(self.button.type.url)
            return self.button.type.url
        elif isinstance(self.button.type, types.InlineButtonTypeGame):
            req = functions.messages.GetBotCallbackAnswerRequest(
                peer=self._chat, msg_id=self._msg_id, game=True
            )
            try:
                return await self._client(req)
            except BotResponseTimeoutError:
                return None
        elif isinstance(self.button.type, types.ButtonTypeRequestPhone):
            if not share_phone:
                raise ValueError(
                    "cannot click on phone buttons unless share_phone=True"
                )

            if share_phone == True or isinstance(share_phone, str):
                me = await self._client.get_me()
                share_phone = types.InputMediaContact(
                    phone_number=me.phone if share_phone == True else share_phone,
                    first_name=me.first_name or "",
                    last_name=me.last_name or "",
                    vcard="",
                )

            return await self._client.send_file(self._chat, share_phone)
        elif isinstance(self.button.type, types.ButtonTypeRequestGeoLocation):
            if not share_geo:
                raise ValueError(
                    "cannot click on geo buttons unless share_geo=(longitude, latitude)"
                )

            if isinstance(share_geo, (tuple, list)):
                long, lat = share_geo
                share_geo = types.InputMediaGeoPoint(
                    types.InputGeoPoint(lat=lat, long=long)
                )

            return await self._client.send_file(self._chat, share_geo)
