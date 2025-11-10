import typing
import re

from .. import errors
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


    async def upgrade_gift(
            self: 'TelegramClient',
            owned_gift_id: str,
            keep_original_details: bool = None,
            star_count: int = None,
    ) -> types.payments.PaymentResult:
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