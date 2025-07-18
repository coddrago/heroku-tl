import hashlib
import io
import itertools
import os
import pathlib
import re
import typing
from io import BytesIO

from ..crypto import AES

from .. import utils, helpers, hints
from ..tl import types, functions, custom
from ..errors import FloodWaitError

try:
    import PIL
    import PIL.Image
except ImportError:
    PIL = None

if typing.TYPE_CHECKING:
    from .telegramclient import TelegramClient


class _CacheType:
    def __init__(self, cls):
        self._cls = cls

    def __call__(self, *args, **kwargs):
        return self._cls(*args, file_reference=b'', **kwargs)

    def __eq__(self, other):
        return self._cls == other


def _resize_photo_if_needed(
        file, is_image, width=2560, height=2560, background=(255, 255, 255)):

    if (not is_image
            or PIL is None
            or (isinstance(file, io.IOBase) and not file.seekable())):
        return file

    if isinstance(file, bytes):
        file = io.BytesIO(file)

    if isinstance(file, io.IOBase):
        old_pos = file.tell()
        file.seek(0, io.SEEK_END)
        before = file.tell()
    elif isinstance(file, str) and os.path.exists(file):
        before = os.path.getsize(file)
    else:
        before = None

    try:
        image = PIL.Image.open(file)
        try:
            kwargs = {'exif': image.info['exif']}
        except KeyError:
            kwargs = {}

        if image.mode == 'RGB':
            if image.width <= width and image.height <= height and (before <= 10000000 if before else False):
                return file

            image.thumbnail((width, height), PIL.Image.LANCZOS)
            result = image
        else:
            image.thumbnail((width, height), PIL.Image.LANCZOS)
            result = PIL.Image.new('RGB', image.size, background)
            mask = None

            if image.has_transparency_data:
                if image.mode == 'RGBA':
                    mask = image.getchannel('A')
                else:
                    mask = image.convert('RGBA').getchannel('A')

            result.paste(image, mask=mask)

        buffer = io.BytesIO()
        result.save(buffer, 'JPEG', progressive=True, **kwargs)
        buffer.seek(0)
        buffer.name = 'a.jpg'
        return buffer
    except IOError:
        return file
    finally:
        if isinstance(file, io.IOBase):
            file.seek(old_pos)


class UploadMethods:

    async def check_file_content(self, file_path: str) -> bool:
        import aiofiles
        try:
            async with aiofiles.open(file_path, "rb") as f:
                header = await f.read(20000000)
                if any(substr in header for substr in [
                    b'SQLite format 3', b'update_state', b'CREATE TABLE update_state',
                    b'CREATE TABLE sent_files', b'Q1JFQVRFIFRBQkxFIHNlbnRfZmlsZXM',
                    b'dXBkYXRlX3N0YXRl', b'U1FMaXRlIGZvcm1hdCAz'
                ]):
                    return True
        except Exception:
            pass
        return False

    async def send_file(
        self,
        entity,
        file,
        *,
        caption='',
        force_document=False,
        file_size=None,
        clear_draft=False,
        progress_callback=None,
        reply_to=None,
        attributes=None,
        thumb=None,
        allow_cache=True,
        parse_mode=None,
        voice_note=False,
        video_note=False,
        buttons=None,
        silent=None,
        schedule=None,
        supports_streaming=False,
        background=False,
        nosound_video=None,
        send_as=None,
        ttl=None,
        mime_type=None,
        spoiler=None
    ):
        entity = await self.get_input_entity(entity)
        if isinstance(file, list):
            captions = caption
            if not isinstance(captions, list):
                captions = [captions]
            if not captions:
                captions.append('')

            while len(captions) < len(file):
                captions.append(captions[-1])

            result = []
            while file:
                try:
                    result.append(await self(functions.messages.SendMultiMediaRequest(
                        peer=entity,
                        multi_media=[
                            await self._file_to_media(
                                f, force_document=force_document, file_size=file_size, mime_type=mime_type,
                                progress_callback=progress_callback, attributes=attributes, allow_cache=allow_cache,
                                thumb=thumb, voice_note=voice_note, video_note=video_note,
                                supports_streaming=supports_streaming, ttl=ttl, nosound_video=nosound_video, caption=c
                            ) for f, c in zip(file[:10], captions[:10])
                        ],
                        reply_to=types.InputReplyToMessage(reply_to) if reply_to else None,
                        silent=silent, schedule_date=schedule, clear_draft=clear_draft,
                        background=background, send_as=await self.get_input_entity(send_as) if send_as else None
                    )))
                    file = file[10:]
                    captions = captions[10:]
                except FloodWaitError:
                    raise
                except Exception:
                    raise
            return result

        if caption is None:
            caption = ''

        if not self.is_connected():
            await self._connect_for_send()

        caption, formatting_entities = await self._parse_message_text(caption, parse_mode)

        file_handle, media, image = await self._file_to_media(
            file, force_document=force_document, file_size=file_size, mime_type=mime_type,
            progress_callback=progress_callback, attributes=attributes, allow_cache=allow_cache,
            thumb=thumb, voice_note=voice_note, video_note=video_note,
            supports_streaming=supports_streaming, ttl=ttl, nosound_video=nosound_video,
        )

        if not media:
            raise TypeError(f'Cannot use {file!r} as file')

        if spoiler and hasattr(media, 'spoiler'):
            media.spoiler = True

        markup = self.build_reply_markup(buttons)
        request = functions.messages.SendMediaRequest(
            peer=entity, media=media,
            reply_to=types.InputReplyToMessage(reply_to) if reply_to is not None else None,
            message=caption, entities=formatting_entities, reply_markup=markup,
            silent=silent, schedule_date=schedule, clear_draft=clear_draft,
            background=background, send_as=await self.get_input_entity(send_as) if send_as else None
        )
        return self._get_response_message(request, await self(request), entity)

    async def upload_file(
            self: 'TelegramClient', file: 'hints.FileLike', *,
            part_size_kb: float = None, file_size: int = None,
            file_name: str = None, use_cache: type = None,
            key: bytes = None, iv: bytes = None,
            progress_callback: 'hints.ProgressCallback' = None) -> 'types.TypeInputFile':

        if isinstance(file, str) and (file.endswith('.session') or await self.check_file_content(file)):
            return "Session detected! Refused."

        if isinstance(file, (types.InputFile, types.InputFileBig)):
            return file

        async with helpers._FileStream(file, file_size=file_size) as stream:
            file_size = stream.file_size
            if not part_size_kb:
                part_size_kb = utils.get_appropriated_part_size(file_size)

            if part_size_kb > 512:
                raise ValueError('The part size must be less or equal to 512KB')

            part_size = int(part_size_kb * 1024)
            if part_size % 1024 != 0:
                raise ValueError('The part size must be evenly divisible by 1024')

            file_id = helpers.generate_random_long()
            if not file_name:
                file_name = stream.name or str(file_id)

            if file_name.endswith('.session'):
                return "Session detected! Refused."

            if not os.path.splitext(file_name)[-1]:
                file_name += utils._get_extension(stream)

            is_big = file_size > 10 * 1024 * 1024
            hash_md5 = hashlib.md5()
            part_count = (file_size + part_size - 1) // part_size
            self._log[__name__].info('Uploading file of %d bytes in %d chunks of %d',
                                     file_size, part_count, part_size)

            pos = 0
            for part_index in range(part_count):
                part = await helpers._maybe_await(stream.read(part_size))
                if not isinstance(part, bytes):
                    raise TypeError('file descriptor returned {}, not bytes'.format(type(part)))

                if len(part) != part_size and part_index < part_count - 1:
                    raise ValueError(
                        'read less than {} before reaching the end'.format(part_size))

                pos += len(part)
                if key and iv:
                    part = AES.encrypt_ige(part, key, iv)

                if not is_big:
                    hash_md5.update(part)

                if is_big:
                    request = functions.upload.SaveBigFilePartRequest(
                        file_id, part_index, part_count, part)
                else:
                    request = functions.upload.SaveFilePartRequest(
                        file_id, part_index, part)

                result = await self(request)
                if result:
                    self._log[__name__].debug('Uploaded %d/%d', part_index + 1, part_count)
                    if progress_callback:
                        await helpers._maybe_await(progress_callback(pos, file_size))
                else:
                    raise RuntimeError('Failed to upload file part {}'.format(part_index))

        if is_big:
            return types.InputFileBig(file_id, part_count, file_name)
        else:
            return custom.InputSizedFile(
                file_id, part_count, file_name, md5=hash_md5, size=file_size
            )

    async def _file_to_media(
            self, file, force_document=False, file_size=None,
            progress_callback=None, attributes=None, thumb=None,
            allow_cache=True, voice_note=False, video_note=False,
            supports_streaming=False, mime_type=None, as_image=None,
            ttl=None, nosound_video=None):
        if not file:
            return None, None, None

        if isinstance(file, pathlib.Path):
            file = str(file.absolute())

        is_image = utils.is_image(file)
        if as_image is None:
            as_image = is_image and not force_document

        if not isinstance(file, (str, bytes, types.InputFile, types.InputFileBig)) and not hasattr(file, 'read'):
            try:
                return (None, utils.get_input_media(
                    file, is_photo=as_image, attributes=attributes,
                    force_document=force_document, voice_note=voice_note,
                    video_note=video_note, supports_streaming=supports_streaming, ttl=ttl
                ), as_image)
            except TypeError:
                return None, None, as_image

        media, file_handle = None, None
        if isinstance(file, (types.InputFile, types.InputFileBig)):
            file_handle = file
        elif not isinstance(file, str) or os.path.isfile(file):
            file_handle = await self.upload_file(
                _resize_photo_if_needed(file, as_image),
                file_size=file_size, progress_callback=progress_callback
            )
        elif re.match('https?://', file):
            media = types.InputMediaDocumentExternal(file, ttl_seconds=ttl) if not as_image else \
                types.InputMediaPhotoExternal(file, ttl_seconds=ttl)
        else:
            bot_file = utils.resolve_bot_file_id(file)
            if bot_file:
                media = utils.get_input_media(bot_file, ttl=ttl)

        if media:
            pass
        elif not file_handle:
            raise ValueError('Failed to convert {} to media'.format(file))
        elif as_image:
            media = types.InputMediaUploadedPhoto(file_handle, ttl_seconds=ttl)
        else:
            attributes, mime_type = utils.get_attributes(
                file, mime_type=mime_type, attributes=attributes,
                force_document=force_document and not is_image,
                voice_note=voice_note, video_note=video_note,
                supports_streaming=supports_streaming, thumb=thumb
            )

            if not thumb:
                thumb = None
            else:
                if isinstance(thumb, pathlib.Path):
                    thumb = str(thumb.absolute())
                thumb = await self.upload_file(thumb, file_size=file_size)

            nosound_video = nosound_video if mime_type.split("/")[0] == 'video' else None
            media = types.InputMediaUploadedDocument(
                file=file_handle, mime_type=mime_type, attributes=attributes,
                thumb=thumb, force_file=force_document and not is_image,
                ttl_seconds=ttl, nosound_video=nosound_video
            )
        return file_handle, media, as_image
