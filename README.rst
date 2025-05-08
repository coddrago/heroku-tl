# Herokutl

> ⭐️ Thanks **everyone** who has starred the project, it means a lot!

![logo](logo.svg) **Telethon** is an [asyncio](https://docs.python.org/3/library/asyncio.html) **Python 3** [MTProto](https://core.telegram.org/mtproto) library to interact with [Telegram](https://telegram.org)'s API as a user or through a bot account (bot API alternative).

> **Important**: If you have code using Telethon before its 1.0 version, you must read [Compatibility and Convenience](https://docs.telethon.dev/en/stable/misc/compatibility-and-convenience.html) to learn how to migrate. As with any third-party library for Telegram, be careful not to break [Telegram's ToS](https://core.telegram.org/api/terms) or [Telegram can ban the account](https://docs.telethon.dev/en/stable/quick-references/faq.html#my-account-was-deleted-limited-when-using-the-library).

## What is this?

Telegram is a popular messaging application. This library is meant to make it easy for you to write Python programs that can interact with Telegram. Think of it as a wrapper that has already done the heavy job for you, so you can focus on developing an application.

## Installing

```sh
pip3 install heroku-tl-new
```

## Creating a client

```python
from herokutl import TelegramClient, events, sync

# These example values won't work. You must get your own api_id and
# api_hash from https://my.telegram.org, under API Development.
api_id = 12345
api_hash = '0123456789abcdef0123456789abcdef'

client = TelegramClient('session_name', api_id, api_hash)
client.start()
```

## Doing stuff

```python
print(client.get_me().stringify())

client.send_message('username', 'Hello! Talking to you from Telethon')
client.send_file('username', '/home/myself/Pictures/holidays.jpg')

client.download_profile_photo('me')
messages = client.get_messages('username')
messages[0].download_media()

@client.on(events.NewMessage(pattern='(?i)hi|hello'))
async def handler(event):
    await event.respond('Hey!')
```

## Next steps

Do you like how Telethon looks? Check out [Read The Docs](https://docs.telethon.dev) for a more in-depth explanation, with examples, troubleshooting issues, and more useful information.