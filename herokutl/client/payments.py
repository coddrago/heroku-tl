import typing
import re

from .. import errors, hints
from ..tl import types, functions

if typing.TYPE_CHECKING:
    from .telegramclient import TelegramClient

class GiftMethods:
    async def _get_input_stargift(self: 'TelegramClient', owned_gift_id: str) -> "types.TypeInputSavedStarGift":
        if not isinstance(owned_gift_id, str):
            raise ValueError(f"owned_gift_id has to be str, but {type(owned_gift_id)} was provided")
        
        saved_gift_match = re.compile(r"^(-\d+)_(\d+)$").match(owned_gift_id)
        slug_match = re.compile(r"^(?:https?://)?(?:www\.)?(?:t(?:elegram)?\.(?:org|me|dog)/(?:nft/|\+))([\w-]+)$").match(owned_gift_id)

        if saved_gift_match:
            return types.InputSavedStarGiftChat(
                peer=await self.get_input_entity(int(saved_gift_match.group(1))),
                saved_id=int(saved_gift_match.group(2))
            )
        elif slug_match:
            return types.InputSavedStarGiftSlug(
                slug=slug_match.group(1)
            )
        else:
            return types.InputSavedStarGiftUser(
                msg_id=int(owned_gift_id)
            )


    async def get_saved_gifts(
            self: 'TelegramClient',
            peer: 'hints.EntityLike',
            collection_id: int = None,
            exclude_unsaved: bool = None,
            exclude_saved: bool = None,
            exclude_unlimited: bool = None,
            exclude_upgradable: bool = None,
            exclude_unupgradable: bool = None,
            exclude_nft: bool = None,
            sort_by_price: bool = None,
            limit: int = 0,
            offset: str = "",
    ) -> 'typing.AsyncGenerator["types.payments.SavedStarGift", None]':
        
        current = 0
        total = limit or (1 << 31) - 1
        limit = min(100, limit)

        while True:
            r: types.payments.SavedStarGifts = await self(
                functions.payments.GetSavedStarGiftsRequest(
                    peer=peer,
                    offset=offset,
                    limit=limit,
                    exclude_unsaved=exclude_unsaved,
                    exclude_saved=exclude_saved,
                    exclude_unlimited=exclude_unlimited,
                    exclude_unique=exclude_nft,
                    exclude_upgradable=exclude_upgradable,
                    exclude_unupgradable=exclude_unupgradable,
                    sort_by_value=sort_by_price,
                    collection_id=collection_id
                ),
                flood_sleep_threshold=60
            )

            gifts = [
                custom.StarGift._parse(self, gift)
                for gift in r.gifts
            ]

            if not gifts:
                return
            
            for gift in gifts:
                yield gift

                current += 1

                if current >= total:
                    return
                
            offset = r.next_offset

            if not offset:
                return


    async def upgrade_gift(
            self: 'TelegramClient',
            owned_gift_id: str,
            keep_original_details: bool = None,
            star_count: int = None,
    ) -> 'types.payments.PaymentResult':
        stargift = await self._get_input_stargift(owned_gift_id)

        try:
            r = await self(
                functions.payments.UpgradeStarGiftRequest(
                    stargift=stargift,
                    keep_original_details=keep_original_details
                )
            )
        except errors.PaymentRequiredError:
            invoice = types.InputInvoiceStarGiftUpgrade(
                stargift=stargift,
                keep_original_details=keep_original_details
            )

            form = await self(
                functions.payments.GetPaymentFormRequest(
                    invoice=invoice
                )
            )

            if star_count is not None:
                if star_count < 0:
                    raise ValueError("Invalid amount of Telegram Stars specified.")

                if form.invoice.prices[0].amount > star_count:
                    raise ValueError("Have not enough Telegram Stars.")

            r = await self(
                functions.payments.SendStarsFormRequest(
                    form_id=form.form_id,
                    invoice=invoice
                )
            )

        return r
