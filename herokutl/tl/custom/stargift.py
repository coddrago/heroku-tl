from ...client import TelegramClient
from ..types import TypeStarGift, TypePeer, TypeTextWithEntities, SavedStarGift, StarGiftUnique
from ..types.payments import PaymentResult

from typing import Optional, List
from datetime import datetime

class StarGift:

    # region Initialization

    def __init__(
            self,
            client: 'TelegramClient',
            date: Optional[datetime],
            gift: 'TypeStarGift',
            name_hidden: Optional[bool]=None,
            unsaved: Optional[bool]=None,
            refunded: Optional[bool]=None,
            can_upgrade: Optional[bool]=None,
            pinned_to_top: Optional[bool]=None,
            upgrade_separate: Optional[bool]=None,
            from_id: Optional['TypePeer']=None,
            message: Optional['TypeTextWithEntities']=None,
            msg_id: Optional[int]=None,
            saved_id: Optional[int]=None,
            convert_stars: Optional[int]=None,
            upgrade_stars: Optional[int]=None,
            can_export_at: Optional[int]=None,
            transfer_stars: Optional[int]=None, 
            can_transfer_at: Optional[int]=None,
            can_resell_at: Optional[int]=None,
            collection_id: Optional[List[int]]=None,
            prepaid_upgrade_hash: Optional[str]=None
        ):
        self.date = date
        self.gift = gift
        self.name_hidden = name_hidden
        self.unsaved = unsaved
        self.refunded = refunded
        self.can_upgrade = can_upgrade
        self.pinned_to_top = pinned_to_top
        self.upgrade_separate = upgrade_separate
        self.from_id = from_id
        self.message = message
        self.msg_id = msg_id
        self.saved_id = saved_id
        self.convert_stars = convert_stars
        self.upgrade_stars = upgrade_stars
        self.can_export_at = can_export_at
        self.transfer_stars = transfer_stars
        self.can_transfer_at = can_transfer_at
        self.can_resell_at = can_resell_at
        self.collection_id = collection_id
        self.prepaid_upgrade_hash = prepaid_upgrade_hash

        self._client = client

    @staticmethod
    def _parse(
        client,
        gift: 'SavedStarGift',
    ):
        return StarGift(
            date=gift.date,
            gift=gift,
            name_hidden=gift.name_hidden,
            unsaved=gift.unsaved,
            refunded=gift.refunded,
            can_upgrade=gift.can_upgrade,
            pinned_to_top=gift.pinned_to_top,
            upgrade_separate=gift.upgrade_separate,
            from_id=gift.from_id,
            message=gift.message,
            msg_id=gift.msg_id,
            saved_id=gift.saved_id,
            convert_stars=gift.convert_stars,
            upgrade_stars=gift.upgrade_stars,
            can_export_at=gift.can_export_at,
            transfer_stars=gift.transfer_stars,
            can_transfer_at=gift.can_transfer_at,
            can_resell_at=gift.can_resell_at,
            collection_id=gift.collection_id,
            prepaid_upgrade_hash=gift.prepaid_upgrade_hash,
            client=client,
        )



    # endregion Initialization

    # region Public Methods

    async def upgrade(self, keep_original_details: Optional[bool] = None, star_count: Optional[int] = None) -> PaymentResult:
        return await self._client.upgrade_gift(
            owned_gift_id=str(self.msg_id),
            keep_original_details=keep_original_details,
            star_count=star_count
        )