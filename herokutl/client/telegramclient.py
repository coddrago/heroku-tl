from . import (
    AccountMethods,
    AuthMethods,
    DownloadMethods,
    DialogMethods,
    ChatMethods,
    BotMethods,
    MessageMethods,
    UploadMethods,
    ButtonMethods,
    GiftMethods,
    UpdateMethods,
    MessageParseMethods,
    UserMethods,
    TelegramBaseClient,
)


class TelegramClient(
    AccountMethods,
    AuthMethods,
    DownloadMethods,
    DialogMethods,
    ChatMethods,
    BotMethods,
    MessageMethods,
    UploadMethods,
    ButtonMethods,
    GiftMethods,
    UpdateMethods,
    MessageParseMethods,
    UserMethods,
    TelegramBaseClient,
):
    pass
