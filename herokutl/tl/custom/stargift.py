from ..types import (
    TypeStarGift,
    TypePeer,
    TypeTextWithEntities,
    SavedStarGift,
    StarGift as RawStarGift,
    StarGiftUnique,
)
from ..types.payments import PaymentResult

from typing import TYPE_CHECKING, Optional, List
from datetime import datetime

if TYPE_CHECKING:
    from ...client import TelegramClient


class StarGift:

    # region Initialization

    def __init__(
        self,
        client: "TelegramClient",
        date: Optional[datetime] = None,
        gift: Optional["TypeStarGift"] = None,
        *,
        raw: Optional["TypeStarGift"] = None,
        saved_gift: Optional["SavedStarGift"] = None,
        id: Optional[int] = None,
        sticker=None,
        star_count: Optional[int] = None,
        title: Optional[str] = None,
        name: Optional[str] = None,
        regular_gift_id: Optional[int] = None,
        unique_gift_number: Optional[int] = None,
        owner_id: Optional["TypePeer"] = None,
        owner_name: Optional[str] = None,
        owner_address: Optional[str] = None,
        attributes: Optional[list] = None,
        released_by: Optional["TypePeer"] = None,
        gift_address: Optional[str] = None,
        background=None,
        received_gift_id: Optional[str] = None,
        name_hidden: Optional[bool] = None,
        unsaved: Optional[bool] = None,
        refunded: Optional[bool] = None,
        can_upgrade: Optional[bool] = None,
        pinned_to_top: Optional[bool] = None,
        upgrade_separate: Optional[bool] = None,
        from_id: Optional["TypePeer"] = None,
        message: Optional["TypeTextWithEntities"] = None,
        msg_id: Optional[int] = None,
        saved_id: Optional[int] = None,
        convert_stars: Optional[int] = None,
        upgrade_stars: Optional[int] = None,
        can_export_at: Optional[int] = None,
        transfer_stars: Optional[int] = None,
        can_transfer_at: Optional[int] = None,
        can_resell_at: Optional[int] = None,
        collection_id: Optional[List[int]] = None,
        prepaid_upgrade_hash: Optional[str] = None,
        drop_original_details_stars: Optional[int] = None,
        gift_num: Optional[int] = None,
        can_craft_at: Optional[int] = None,
        availability_remains: Optional[int] = None,
        availability_total: Optional[int] = None,
        availability_issued: Optional[int] = None,
        availability_resale: Optional[int] = None,
        first_sale_date: Optional[int] = None,
        last_sale_date: Optional[int] = None,
        locked_until_date: Optional[int] = None,
        per_user_total: Optional[int] = None,
        per_user_remains: Optional[int] = None,
        auction_slug: Optional[str] = None,
        gifts_per_round: Optional[int] = None,
        auction_start_date: Optional[int] = None,
        upgrade_variants: Optional[int] = None,
        resell_amount: Optional[list] = None,
        resell_min_stars: Optional[int] = None,
        resale_ton_only: Optional[bool] = None,
        value_amount: Optional[int] = None,
        value_currency: Optional[str] = None,
        value_usd_amount: Optional[int] = None,
        theme_peer: Optional["TypePeer"] = None,
        peer_color=None,
        host_id: Optional["TypePeer"] = None,
        offer_min_stars: Optional[int] = None,
        craft_chance_permille: Optional[int] = None,
        limited: Optional[bool] = None,
        limited_per_user: Optional[bool] = None,
        sold_out: Optional[bool] = None,
        birthday: Optional[bool] = None,
        require_premium: Optional[bool] = None,
        peer_color_available: Optional[bool] = None,
        auction: Optional[bool] = None,
        theme_available: Optional[bool] = None,
        burned: Optional[bool] = None,
        crafted: Optional[bool] = None,
    ):
        self._client = client

        self.raw = raw
        self.saved_gift = saved_gift
        self.date = date
        self.gift = gift
        self.id = id
        self.sticker = sticker
        self.stars = star_count
        self.star_count = star_count
        self.title = title
        self.name = name
        self.slug = name
        self.gift_id = regular_gift_id
        self.regular_gift_id = regular_gift_id
        self.num = unique_gift_number
        self.unique_gift_number = unique_gift_number
        self.owner_id = owner_id
        self.owner_name = owner_name
        self.owner_address = owner_address
        self.attributes = attributes
        self.released_by = released_by
        self.gift_address = gift_address
        self.background = background

        self.received_gift_id = received_gift_id
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
        self.collection_ids = collection_id
        self.prepaid_upgrade_hash = prepaid_upgrade_hash
        self.drop_original_details_stars = drop_original_details_stars
        self.gift_num = gift_num
        self.can_craft_at = can_craft_at

        self.availability_remains = availability_remains
        self.availability_total = availability_total
        self.availability_issued = availability_issued
        self.availability_resale = availability_resale
        self.first_sale_date = first_sale_date
        self.last_sale_date = last_sale_date
        self.locked_until_date = locked_until_date
        self.per_user_total = per_user_total
        self.per_user_remains = per_user_remains
        self.auction_slug = auction_slug
        self.gifts_per_round = gifts_per_round
        self.auction_start_date = auction_start_date
        self.upgrade_variants = upgrade_variants
        self.resell_amount = resell_amount
        self.resell_min_stars = resell_min_stars
        self.resale_ton_only = resale_ton_only
        self.value_amount = value_amount
        self.value_currency = value_currency
        self.value_usd_amount = value_usd_amount
        self.theme_peer = theme_peer
        self.peer_color = peer_color
        self.host_id = host_id
        self.offer_min_stars = offer_min_stars
        self.craft_chance_permille = craft_chance_permille

        self.limited = limited
        self.limited_per_user = limited_per_user
        self.sold_out = sold_out
        self.birthday = birthday
        self.require_premium = require_premium
        self.peer_color_available = peer_color_available
        self.auction = auction
        self.theme_available = theme_available
        self.burned = burned
        self.crafted = crafted

        self.is_limited = limited
        self.is_limited_per_user = limited_per_user
        self.is_sold_out = sold_out
        self.is_premium = require_premium
        self.is_for_birthday = birthday
        self.is_auction = auction
        self.is_name_hidden = name_hidden
        self.is_saved = None if unsaved is None else not unsaved
        self.is_pinned = pinned_to_top
        self.is_upgrade_separate = upgrade_separate
        self.is_theme_available = theme_available
        self.is_burned = burned
        self.is_crafted = crafted
        self.has_colors = peer_color_available
        self.can_be_upgraded = can_upgrade
        self.can_be_transferred = (
            can_transfer_at is not None or transfer_stars is not None
        )
        self.can_send_purchase_offer = offer_min_stars is not None
        self.was_refunded = refunded

        self.default_sell_star_count = convert_stars
        self.convert_star_count = convert_stars
        self.upgrade_star_count = upgrade_stars
        self.transfer_star_count = transfer_stars
        self.drop_original_details_star_count = drop_original_details_stars
        self.minimum_resell_star_count = resell_min_stars
        self.minimum_offer_star_count = offer_min_stars
        self.available_resale_count = availability_resale
        self.total_upgraded_count = availability_issued
        self.max_upgraded_count = availability_total
        self.unique_gift_variant_count = upgrade_variants
        self.craft_probability_per_mille = craft_chance_permille

    @staticmethod
    def _parse_regular(client, gift: "RawStarGift"):
        return StarGift(
            client=client,
            raw=gift,
            gift=gift,
            id=gift.id,
            sticker=gift.sticker,
            star_count=gift.stars,
            convert_stars=gift.convert_stars,
            upgrade_stars=gift.upgrade_stars,
            title=gift.title,
            released_by=gift.released_by,
            background=gift.background,
            availability_remains=gift.availability_remains,
            availability_total=gift.availability_total,
            availability_resale=gift.availability_resale,
            first_sale_date=gift.first_sale_date,
            last_sale_date=gift.last_sale_date,
            locked_until_date=gift.locked_until_date,
            per_user_total=gift.per_user_total,
            per_user_remains=gift.per_user_remains,
            auction_slug=gift.auction_slug,
            gifts_per_round=gift.gifts_per_round,
            auction_start_date=gift.auction_start_date,
            upgrade_variants=gift.upgrade_variants,
            resell_min_stars=gift.resell_min_stars,
            limited=gift.limited,
            limited_per_user=gift.limited_per_user,
            sold_out=gift.sold_out,
            birthday=gift.birthday,
            require_premium=gift.require_premium,
            peer_color_available=gift.peer_color_available,
            auction=gift.auction,
        )

    @staticmethod
    def _parse_upgraded(client, gift: "StarGiftUnique"):
        return StarGift(
            client=client,
            raw=gift,
            gift=gift,
            id=gift.id,
            title=gift.title,
            name=gift.slug,
            regular_gift_id=gift.gift_id,
            unique_gift_number=gift.num,
            owner_id=gift.owner_id,
            owner_name=gift.owner_name,
            owner_address=gift.owner_address,
            attributes=gift.attributes,
            released_by=gift.released_by,
            gift_address=gift.gift_address,
            availability_total=gift.availability_total,
            availability_issued=gift.availability_issued,
            resell_amount=gift.resell_amount,
            resale_ton_only=gift.resale_ton_only,
            value_amount=gift.value_amount,
            value_currency=gift.value_currency,
            value_usd_amount=gift.value_usd_amount,
            theme_peer=gift.theme_peer,
            peer_color=gift.peer_color,
            host_id=gift.host_id,
            offer_min_stars=gift.offer_min_stars,
            craft_chance_permille=gift.craft_chance_permille,
            require_premium=gift.require_premium,
            theme_available=gift.theme_available,
            burned=gift.burned,
            crafted=gift.crafted,
        )

    @staticmethod
    def _parse(
        client,
        gift: "SavedStarGift",
    ):
        if isinstance(gift.gift, RawStarGift):
            parsed_gift = StarGift._parse_regular(client, gift.gift)
        elif isinstance(gift.gift, StarGiftUnique):
            parsed_gift = StarGift._parse_upgraded(client, gift.gift)
        else:
            return None

        parsed_gift.raw = gift
        parsed_gift.saved_gift = gift
        parsed_gift.date = gift.date
        parsed_gift.received_gift_id = (
            str(gift.msg_id or gift.saved_id) if gift.msg_id or gift.saved_id else None
        )
        parsed_gift.name_hidden = gift.name_hidden
        parsed_gift.unsaved = gift.unsaved
        parsed_gift.refunded = gift.refunded
        parsed_gift.can_upgrade = gift.can_upgrade
        parsed_gift.pinned_to_top = gift.pinned_to_top
        parsed_gift.upgrade_separate = gift.upgrade_separate
        parsed_gift.from_id = gift.from_id
        parsed_gift.message = gift.message
        parsed_gift.msg_id = gift.msg_id
        parsed_gift.saved_id = gift.saved_id
        parsed_gift.convert_stars = gift.convert_stars
        parsed_gift.upgrade_stars = gift.upgrade_stars
        parsed_gift.can_export_at = gift.can_export_at
        parsed_gift.transfer_stars = gift.transfer_stars
        parsed_gift.can_transfer_at = gift.can_transfer_at
        parsed_gift.can_resell_at = gift.can_resell_at
        parsed_gift.collection_id = gift.collection_id
        parsed_gift.collection_ids = gift.collection_id
        parsed_gift.prepaid_upgrade_hash = gift.prepaid_upgrade_hash
        parsed_gift.drop_original_details_stars = gift.drop_original_details_stars
        parsed_gift.gift_num = gift.gift_num
        parsed_gift.can_craft_at = gift.can_craft_at

        parsed_gift.is_name_hidden = gift.name_hidden
        parsed_gift.is_saved = not gift.unsaved
        parsed_gift.is_pinned = gift.pinned_to_top
        parsed_gift.is_upgrade_separate = gift.upgrade_separate
        parsed_gift.can_be_upgraded = gift.can_upgrade
        parsed_gift.can_be_transferred = (
            gift.can_transfer_at is not None or gift.transfer_stars is not None
        )
        parsed_gift.was_refunded = gift.refunded
        parsed_gift.convert_star_count = (
            gift.convert_stars or parsed_gift.convert_star_count
        )
        parsed_gift.upgrade_star_count = (
            gift.upgrade_stars or parsed_gift.upgrade_star_count
        )
        parsed_gift.transfer_star_count = (
            gift.transfer_stars or parsed_gift.transfer_star_count
        )
        parsed_gift.drop_original_details_star_count = (
            gift.drop_original_details_stars
            or parsed_gift.drop_original_details_star_count
        )
        parsed_gift.unique_gift_number = gift.gift_num or parsed_gift.unique_gift_number

        return parsed_gift

    def to_dict(self):
        return {
            "_": "StarGift",
            "id": self.id,
            "date": self.date,
            "gift": self.gift,
            "raw": self.raw,
            "saved_gift": self.saved_gift,
            "name_hidden": self.name_hidden,
            "unsaved": self.unsaved,
            "refunded": self.refunded,
            "can_upgrade": self.can_upgrade,
            "pinned_to_top": self.pinned_to_top,
            "upgrade_separate": self.upgrade_separate,
            "from_id": self.from_id,
            "message": self.message,
            "msg_id": self.msg_id,
            "saved_id": self.saved_id,
            "convert_stars": self.convert_stars,
            "upgrade_stars": self.upgrade_stars,
            "can_export_at": self.can_export_at,
            "transfer_stars": self.transfer_stars,
            "can_transfer_at": self.can_transfer_at,
            "can_resell_at": self.can_resell_at,
            "collection_id": self.collection_id,
            "prepaid_upgrade_hash": self.prepaid_upgrade_hash,
            "drop_original_details_stars": self.drop_original_details_stars,
            "gift_num": self.gift_num,
            "can_craft_at": self.can_craft_at,
            "received_gift_id": self.received_gift_id,
            "sticker": self.sticker,
            "stars": self.stars,
            "star_count": self.star_count,
            "title": self.title,
            "slug": self.slug,
            "name": self.name,
            "gift_id": self.gift_id,
            "regular_gift_id": self.regular_gift_id,
            "num": self.num,
            "unique_gift_number": self.unique_gift_number,
            "owner_id": self.owner_id,
            "owner_name": self.owner_name,
            "owner_address": self.owner_address,
            "attributes": self.attributes,
            "released_by": self.released_by,
            "background": self.background,
            "availability_remains": self.availability_remains,
            "availability_total": self.availability_total,
            "availability_issued": self.availability_issued,
            "availability_resale": self.availability_resale,
            "available_resale_count": self.available_resale_count,
            "total_upgraded_count": self.total_upgraded_count,
            "max_upgraded_count": self.max_upgraded_count,
            "unique_gift_variant_count": self.unique_gift_variant_count,
            "first_sale_date": self.first_sale_date,
            "last_sale_date": self.last_sale_date,
            "locked_until_date": self.locked_until_date,
            "per_user_total": self.per_user_total,
            "per_user_remains": self.per_user_remains,
            "auction_slug": self.auction_slug,
            "gifts_per_round": self.gifts_per_round,
            "auction_start_date": self.auction_start_date,
            "upgrade_variants": self.upgrade_variants,
            "gift_address": self.gift_address,
            "resell_amount": self.resell_amount,
            "resell_min_stars": self.resell_min_stars,
            "minimum_resell_star_count": self.minimum_resell_star_count,
            "resale_ton_only": self.resale_ton_only,
            "value_amount": self.value_amount,
            "value_currency": self.value_currency,
            "value_usd_amount": self.value_usd_amount,
            "theme_peer": self.theme_peer,
            "peer_color": self.peer_color,
            "host_id": self.host_id,
            "offer_min_stars": self.offer_min_stars,
            "craft_chance_permille": self.craft_chance_permille,
            "default_sell_star_count": self.default_sell_star_count,
            "convert_star_count": self.convert_star_count,
            "upgrade_star_count": self.upgrade_star_count,
            "transfer_star_count": self.transfer_star_count,
            "drop_original_details_star_count": self.drop_original_details_star_count,
            "is_limited": self.is_limited,
            "is_limited_per_user": self.is_limited_per_user,
            "is_sold_out": self.is_sold_out,
            "is_premium": self.is_premium,
            "is_for_birthday": self.is_for_birthday,
            "is_auction": self.is_auction,
            "is_name_hidden": self.is_name_hidden,
            "is_saved": self.is_saved,
            "is_pinned": self.is_pinned,
            "is_upgrade_separate": self.is_upgrade_separate,
            "is_theme_available": self.is_theme_available,
            "is_burned": self.is_burned,
            "is_crafted": self.is_crafted,
            "can_be_upgraded": self.can_be_upgraded,
            "can_be_transferred": self.can_be_transferred,
            "can_send_purchase_offer": self.can_send_purchase_offer,
            "was_refunded": self.was_refunded,
        }

    # endregion Initialization

    # region Public Methods

    async def upgrade(
        self,
        keep_original_details: Optional[bool] = None,
        star_count: Optional[int] = None,
    ) -> PaymentResult:
        return await self._client.upgrade_gift(
            owned_gift_id=str(self.msg_id),
            keep_original_details=keep_original_details,
            star_count=star_count,
        )

    # endregion Public Methods
