"""
Database storage for deals (web app)
"""
from typing import Optional
from datetime import datetime, timedelta, timezone
import uuid
import secrets

from sqlalchemy import or_

from backend.database.connection import get_db_session, ensure_tables
from backend.database.models import DealModel, DealStatus

# Ensure tables exist on import
ensure_tables()


def generate_deal_id() -> str:
    """Generate unique deal ID"""
    return str(uuid.uuid4())


def generate_link_token() -> str:
    """Generate unique shareable link token (URL-safe)"""
    return secrets.token_urlsafe(16)


def create_deal(
    title: str,
    price_sats: int,
    creator_role: str = 'seller',
    seller_id: str = None,
    seller_name: str = None,
    buyer_id: str = None,
    buyer_name: str = None,
    description: str = None,
    timeout_hours: int = 72,
    timeout_action: str = 'refund',
    requires_tracking: bool = False,
    recovery_contact: str = None
) -> dict:
    """
    Create a new deal

    creator_role: 'seller' or 'buyer' - who is creating the deal
    If creator_role='seller': seller_id required, buyer joins later
    If creator_role='buyer': buyer_id required, seller joins later

    Returns deal dict including shareable link token.
    """
    deal_id = generate_deal_id()
    link_token = generate_link_token()

    deal = DealModel(
        deal_id=deal_id,
        deal_link_token=link_token,
        creator_role=creator_role,
        seller_id=seller_id,
        seller_name=seller_name,
        buyer_id=buyer_id,
        buyer_name=buyer_name,
        title=title,
        description=description,
        price_sats=price_sats,
        timeout_hours=timeout_hours,
        timeout_action=timeout_action,
        requires_tracking=requires_tracking,
        seller_recovery_contact=recovery_contact if creator_role == 'seller' else None,
        buyer_recovery_contact=recovery_contact if creator_role == 'buyer' else None,
        status=DealStatus.PENDING.value,
        created_at=datetime.now(timezone.utc)
    )

    with get_db_session() as db:
        db.add(deal)
        db.flush()
        return deal.to_dict()


def get_deal_by_id(deal_id: str) -> Optional[dict]:
    """Get deal by ID"""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if deal:
            return deal.to_dict()
        return None


def get_secret_code_hash(deal_id: str) -> Optional[str]:
    """Get the fedimint_secret_code_hash directly from the model (not exposed via to_dict)."""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()
        if deal:
            return deal.fedimint_secret_code_hash
        return None


def get_deal_by_payment_hash(payment_hash_hex: str) -> Optional[dict]:
    """Get deal by LN payment hash"""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.ln_payment_hash == payment_hash_hex
        ).first()

        if deal:
            return deal.to_dict()
        return None


def get_deal_by_token(token: str) -> Optional[dict]:
    """Get deal by shareable link token"""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_link_token == token
        ).first()

        if deal:
            return deal.to_dict()
        return None


def get_deals_by_user(user_id: str, limit: int = 100) -> list[dict]:
    """Get all deals where user is buyer or seller"""
    with get_db_session() as db:
        deals = db.query(DealModel).filter(
            or_(
                DealModel.seller_id == user_id,
                DealModel.buyer_id == user_id
            )
        ).order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        return [d.to_dict() for d in deals]


def get_deals_by_status(status: str, limit: int = 100) -> list[dict]:
    """Get all deals with a specific status"""
    with get_db_session() as db:
        deals = db.query(DealModel).filter(
            DealModel.status == status
        ).order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        return [d.to_dict() for d in deals]


def get_deals_by_statuses(statuses: list[str], limit: int = 500) -> list[dict]:
    """Get all deals matching any of the given statuses (single query)."""
    with get_db_session() as db:
        deals = db.query(DealModel).filter(
            DealModel.status.in_(statuses)
        ).order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        return [d.to_dict() for d in deals]


def get_deals_with_failed_payouts(limit: int = 100) -> list[dict]:
    """Get all deals where a payout (seller or buyer) failed."""
    with get_db_session() as db:
        deals = db.query(DealModel).filter(
            or_(
                DealModel.payout_status == 'failed',
                DealModel.buyer_payout_status == 'failed'
            ),
            # Exclude deals already fully resolved
            DealModel.status.notin_(['completed', 'refunded'])
        ).order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        return [d.to_dict() for d in deals]


def update_deal(deal_id: str, **updates) -> Optional[dict]:
    """
    Update deal fields

    Returns updated deal dict or None if not found.
    """
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if not deal:
            return None

        for key, value in updates.items():
            if hasattr(deal, key):
                setattr(deal, key, value)

        db.flush()
        return deal.to_dict()


def counterparty_join_deal(
    token: str,
    user_id: str,
    user_name: str = None
) -> Optional[dict]:
    """
    Counterparty joins a deal

    If creator was seller -> buyer joins
    If creator was buyer -> seller joins

    Sets counterparty info and transitions to ACTIVE status.
    Returns updated deal or None if not found/invalid state.
    """
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_link_token == token
        ).first()

        if not deal:
            raise ValueError("Deal not found")

        # Can only join pending deals
        if deal.status != DealStatus.PENDING.value:
            raise ValueError(f"Cannot join deal in status: {deal.status}")

        # Can't join own deal
        if deal.seller_id == user_id or deal.buyer_id == user_id:
            raise ValueError("Cannot join your own deal")

        # Set the counterparty based on creator_role
        if deal.creator_role == 'seller':
            # Creator was seller, so joiner is buyer
            deal.buyer_id = user_id
            deal.buyer_name = user_name
        else:
            # Creator was buyer, so joiner is seller
            deal.seller_id = user_id
            deal.seller_name = user_name

        # Set the correct joined_at timestamp based on who is joining
        if deal.creator_role == 'seller':
            deal.buyer_joined_at = datetime.now(timezone.utc)
        # seller_joined_at doesn't exist as a column — buyer_joined_at is only set for buyers
        deal.status = DealStatus.ACTIVE.value

        db.flush()
        return deal.to_dict()


def atomic_status_transition(deal_id: str, expected_statuses: list, new_status: str,
                             expected_extra: dict = None, **extra_updates) -> Optional[dict]:
    """
    Atomically transition a deal's status only if it's currently in one of the expected states
    AND all expected_extra field values match.

    Args:
        expected_extra: Additional WHERE conditions, e.g. {'payout_status': 'failed'}.
            This is critical for same-status transitions (e.g. 'expired' -> 'expired')
            where the status check alone provides no mutual exclusion.

    Returns updated deal dict on success, None if deal not found or conditions don't match.
    This prevents race conditions where concurrent release+refund could both proceed.
    """
    with get_db_session() as db:
        filters = [
            DealModel.deal_id == deal_id,
            DealModel.status.in_(expected_statuses),
        ]
        if expected_extra:
            for key, value in expected_extra.items():
                if hasattr(DealModel, key):
                    filters.append(getattr(DealModel, key) == value)

        deal = db.query(DealModel).filter(*filters).first()

        if not deal:
            return None

        deal.status = new_status
        for key, value in extra_updates.items():
            if hasattr(deal, key):
                setattr(deal, key, value)

        db.flush()
        return deal.to_dict()


def set_deal_funded(deal_id: str) -> Optional[dict]:
    """Mark deal as funded. Only allowed from pending/active states."""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if not deal:
            return None

        # COIN SAFETY: only transition from pre-funded states
        # If already funded, return existing deal without resetting expires_at
        # (prevents infinite expiry extension via repeated check-ln-invoice polls).
        if deal.status == DealStatus.FUNDED.value:
            return deal.to_dict()
        allowed = [DealStatus.PENDING.value, DealStatus.ACTIVE.value]
        if deal.status not in allowed:
            raise ValueError(
                f"Cannot fund deal {deal_id}: status is '{deal.status}' "
                f"(allowed: {allowed})"
            )

        deal.status = DealStatus.FUNDED.value
        deal.funded_at = datetime.now(timezone.utc)

        # Set expiry based on timeout
        deal.expires_at = datetime.now(timezone.utc) + timedelta(hours=deal.timeout_hours)

        db.flush()
        result = deal.to_dict()

    return result


def set_deal_shipped(
    deal_id: str,
    tracking_carrier: str = None,
    tracking_number: str = None,
    shipping_notes: str = None
) -> Optional[dict]:
    """Mark deal as shipped with optional tracking info"""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id,
            DealModel.status == DealStatus.FUNDED.value,
        ).first()

        if not deal:
            return None

        deal.status = DealStatus.SHIPPED.value
        deal.shipped_at = datetime.now(timezone.utc)
        deal.tracking_carrier = tracking_carrier
        deal.tracking_number = tracking_number
        deal.shipping_notes = shipping_notes

        db.flush()
        result = deal.to_dict()

    return result


def set_deal_completed(deal_id: str) -> Optional[dict]:
    """Mark deal as completed"""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if not deal:
            return None

        deal.status = DealStatus.COMPLETED.value
        deal.completed_at = datetime.now(timezone.utc)

        db.flush()
        return deal.to_dict()


def set_deal_status(deal_id: str, status: str) -> Optional[dict]:
    """Set deal status directly"""
    # Validate status against DealStatus enum
    valid_statuses = {s.value for s in DealStatus}
    if status not in valid_statuses:
        raise ValueError(f"Invalid deal status: {status}. Valid: {valid_statuses}")

    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if not deal:
            return None

        deal.status = status

        db.flush()
        return deal.to_dict()


def delete_deal(deal_id: str) -> bool:
    """Delete deal by ID. Only allowed for unfunded deals (no escrow at risk)."""
    with get_db_session() as db:
        deal = db.query(DealModel).filter(
            DealModel.deal_id == deal_id
        ).first()

        if not deal:
            return False

        # COIN SAFETY: never delete deals that have/had funds locked
        safe_to_delete = [DealStatus.PENDING.value, DealStatus.ACTIVE.value, DealStatus.CANCELLED.value]
        if deal.status not in safe_to_delete:
            raise ValueError(
                f"Cannot delete deal {deal_id}: status is '{deal.status}'. "
                f"Only unfunded deals ({safe_to_delete}) can be deleted."
            )

        db.delete(deal)
        return True


def find_expired_deals() -> list[dict]:
    """Find deals that have expired timeout"""
    with get_db_session() as db:
        now = datetime.now(timezone.utc)
        deals = db.query(DealModel).filter(
            DealModel.expires_at < now,
            DealModel.status.in_([
                DealStatus.FUNDED.value,
                DealStatus.SHIPPED.value,
                # NOTE: DISPUTED excluded — oracle resolution handles disputed deals,
                # timeout handler must not bypass oracles by claiming the escrow directly.
                # NOTE: RELEASING/REFUNDING excluded — those are in-flight payouts,
                # not expired deals. Including them would race with active payout attempts.
            ])
        ).all()

        return [d.to_dict() for d in deals]


def get_all_deals(include_finished: bool = False, limit: int = 100) -> list[dict]:
    """
    Get all deals for admin view

    include_finished: if False, only show active deals (pending, active, funded, shipped, disputed)
                     if True, also include completed, refunded, expired, cancelled
    """
    finished_statuses = [
        DealStatus.COMPLETED.value,
        DealStatus.REFUNDED.value,
        DealStatus.EXPIRED.value,
        DealStatus.CANCELLED.value
    ]

    with get_db_session() as db:
        query = db.query(DealModel)

        if not include_finished:
            query = query.filter(~DealModel.status.in_(finished_statuses))

        deals = query.order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        return [d.to_dict() for d in deals]


def get_deal_stats() -> dict:
    """Get deal statistics"""
    from sqlalchemy import func

    with get_db_session() as db:
        total = db.query(func.count(DealModel.deal_id)).scalar()
        total_value = db.query(func.sum(DealModel.price_sats)).scalar() or 0

        # Count by status
        status_counts = db.query(
            DealModel.status,
            func.count(DealModel.deal_id)
        ).group_by(DealModel.status).all()

        return {
            'total_deals': total,
            'total_value_sats': total_value,
            'by_status': {status: count for status, count in status_counts}
        }


def search_deals(
    title: str = None,
    status_filter: str = None,
    min_sats: int = None,
    max_sats: int = None,
    created_after: str = None,
    created_before: str = None,
    limit: int = 50,
) -> list[dict]:
    """
    Search deals with filters (admin use).

    Args:
        title: Substring match on deal title (case-insensitive).
        status_filter: Exact status match (e.g. 'funded', 'disputed').
        min_sats: Minimum price_sats (inclusive).
        max_sats: Maximum price_sats (inclusive).
        created_after: ISO datetime string — only deals created after this time.
        created_before: ISO datetime string — only deals created before this time.
        limit: Max results (capped at 500).
    """
    from datetime import datetime as dt, timezone as tz

    with get_db_session() as db:
        query = db.query(DealModel)

        if title:
            query = query.filter(DealModel.title.ilike(f'%{title}%'))
        if status_filter:
            valid_statuses = {s.value for s in DealStatus}
            if status_filter not in valid_statuses:
                raise ValueError(f"Invalid status: {status_filter}. Valid: {valid_statuses}")
            query = query.filter(DealModel.status == status_filter)
        if min_sats is not None:
            query = query.filter(DealModel.price_sats >= min_sats)
        if max_sats is not None:
            query = query.filter(DealModel.price_sats <= max_sats)
        if created_after:
            try:
                after_dt = dt.fromisoformat(created_after).replace(tzinfo=tz.utc)
            except ValueError:
                raise ValueError(f"Invalid created_after datetime: {created_after}")
            query = query.filter(DealModel.created_at >= after_dt)
        if created_before:
            try:
                before_dt = dt.fromisoformat(created_before).replace(tzinfo=tz.utc)
            except ValueError:
                raise ValueError(f"Invalid created_before datetime: {created_before}")
            query = query.filter(DealModel.created_at <= before_dt)

        deals = query.order_by(DealModel.created_at.desc()).limit(min(limit, 500)).all()
        return [d.to_dict() for d in deals]


def find_deals_by_linking_pubkey(linking_pubkey: str, limit: int = 50) -> list[dict]:
    """
    Find all deals where the user participated (by their LNURL linking pubkey)

    This allows users to recover their deals after clearing browser storage,
    as long as they authenticate with the same Lightning wallet.
    """
    with get_db_session() as db:
        deals = db.query(DealModel).filter(
            or_(
                DealModel.buyer_linking_pubkey == linking_pubkey,
                DealModel.seller_linking_pubkey == linking_pubkey
            )
        ).order_by(
            DealModel.created_at.desc()
        ).limit(limit).all()

        # Add role info to each deal
        result = []
        for deal in deals:
            deal_dict = deal.to_dict()
            if deal.buyer_linking_pubkey == linking_pubkey:
                deal_dict['user_role'] = 'buyer'
            else:
                deal_dict['user_role'] = 'seller'
            result.append(deal_dict)

        return result


