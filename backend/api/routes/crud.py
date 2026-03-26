"""
Deal CRUD endpoints: create, list, get, join, cancel, delete, search, stats, payout-status
"""
import logging
import os
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Header, status
from datetime import datetime, timezone

from backend.database import deal_storage
from backend.api.security import strip_html_tags, validate_length, MAX_LENGTHS
from backend.database.models import DealStatus
from backend.database.settings import get_limits
from backend.config import CONFIG

from backend.api.routes._shared import (
    _ws_notify, deal_to_response, _verify_deal_signature, verify_admin,
    CreateDealRequest, JoinDealRequest, SignedActionRequest,
    DealResponse, DealListResponse, DealStatsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/stats", response_model=DealStatsResponse)
async def deal_stats(
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """Get deal statistics (admin only)."""
    verify_admin(x_admin_key, x_admin_pubkey)
    try:
        stats = deal_storage.get_deal_stats()
        return DealStatsResponse(**stats)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get statistics"
        )


@router.post("/", response_model=DealResponse, status_code=status.HTTP_201_CREATED)
async def create_deal(request: Request, body: CreateDealRequest):
    """Create a new deal (buyer or seller)"""
    if body.creator_role == 'seller' and not body.seller_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="seller_id required when creator_role is 'seller'"
        )
    if body.creator_role == 'buyer' and not body.buyer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="buyer_id required when creator_role is 'buyer'"
        )

    limits = get_limits()
    if body.price_sats < limits["min_sats"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Amount too low. Minimum is {limits['min_sats']:,} sats."
        )
    if body.price_sats > limits["max_sats"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Amount too high. Maximum is {limits['max_sats']:,} sats."
        )

    sanitized_title = strip_html_tags(body.title)
    sanitized_title = validate_length(sanitized_title, MAX_LENGTHS["title"], "title")

    sanitized_description = strip_html_tags(body.description) if body.description else None
    if sanitized_description:
        sanitized_description = validate_length(sanitized_description, MAX_LENGTHS["description"], "description")

    sanitized_seller_id = strip_html_tags(body.seller_id) if body.seller_id else None
    sanitized_buyer_id = strip_html_tags(body.buyer_id) if body.buyer_id else None
    sanitized_seller_name = strip_html_tags(body.seller_name) if body.seller_name else None
    sanitized_buyer_name = strip_html_tags(body.buyer_name) if body.buyer_name else None

    try:
        deal = deal_storage.create_deal(
            title=sanitized_title,
            price_sats=body.price_sats,
            creator_role=body.creator_role,
            seller_id=sanitized_seller_id,
            seller_name=sanitized_seller_name,
            buyer_id=sanitized_buyer_id,
            buyer_name=sanitized_buyer_name,
            description=sanitized_description,
            timeout_hours=body.timeout_hours,
            timeout_action=body.timeout_action,
            requires_tracking=body.requires_tracking,
            recovery_contact=strip_html_tags(body.recovery_contact) if body.recovery_contact else None
        )

        return deal_to_response(deal)

    except Exception as e:
        logger.error("Failed to create deal: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create deal"
        )


@router.get("/user/{user_id}", response_model=list[DealListResponse])
async def list_user_deals(user_id: str, status_filter: Optional[str] = None):
    """List all deals for a user (as buyer or seller)"""
    try:
        deals = deal_storage.get_deals_by_user(user_id)

        results = []
        for deal in deals:
            if status_filter and deal['status'] != status_filter:
                continue

            role = 'seller' if deal['seller_id'] == user_id else 'buyer'

            results.append(DealListResponse(
                deal_id=deal['deal_id'],
                title=deal['title'],
                status=deal['status'],
                price_sats=deal['price_sats'],
                seller_name=deal.get('seller_name'),
                buyer_name=deal.get('buyer_name'),
                role=role,
                created_at=deal['created_at']
            ))

        return results

    except Exception as e:
        logger.error("Failed to list deals for user %s: %s", user_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list deals"
        )


@router.get("/token/{token}", response_model=DealResponse)
async def get_deal_by_token(token: str):
    """Get deal by shareable link token (public endpoint for buyer)"""
    deal = deal_storage.get_deal_by_token(token)

    if not deal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deal not found"
        )

    creator_exists = deal.get('seller_linking_pubkey') or deal.get('buyer_linking_pubkey')
    if not deal.get('buyer_started_at') and creator_exists:
        now = datetime.now(timezone.utc)
        deal_storage.update_deal(deal_id=deal['deal_id'], buyer_started_at=now)
        deal['buyer_started_at'] = now.isoformat()
        await _ws_notify(deal['deal_id'], 'deal:buyer_started')

    return deal_to_response(deal)


@router.get("/search")
async def search_deals(
    title: Optional[str] = None,
    status_filter: Optional[str] = None,
    min_sats: Optional[int] = None,
    max_sats: Optional[int] = None,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
    limit: int = 50,
    x_admin_key: Optional[str] = Header(None),
    x_admin_pubkey: Optional[str] = Header(None),
):
    """
    Search and filter deals (admin only).

    Supports filtering by title (substring), status, amount range, and date range.
    """
    verify_admin(x_admin_key, x_admin_pubkey)

    if limit > 500:
        limit = 500

    try:
        deals = deal_storage.search_deals(
            title=title,
            status_filter=status_filter,
            min_sats=min_sats,
            max_sats=max_sats,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
        )
        return {"deals": deals, "count": len(deals)}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Search failed: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Search failed")


@router.get("/{deal_id}", response_model=DealResponse)
async def get_deal(deal_id: str):
    """Get deal by ID"""
    deal = deal_storage.get_deal_by_id(deal_id)

    if not deal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deal not found"
        )

    return deal_to_response(deal)


@router.post("/token/{token}/join", response_model=DealResponse)
async def join_deal(token: str, body: JoinDealRequest):
    """Counterparty joins a deal"""
    deal = deal_storage.get_deal_by_token(token)
    if not deal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deal not found"
        )

    if deal['status'] != DealStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot join deal in status: {deal['status']}"
        )

    creator_id = deal['seller_id'] if deal.get('creator_role', 'seller') == 'seller' else deal['buyer_id']
    if creator_id == body.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot join your own deal"
        )

    try:
        updated_deal = deal_storage.counterparty_join_deal(
            token=token,
            user_id=body.user_id,
            user_name=body.user_name
        )

        await _ws_notify(deal['deal_id'], 'deal:joined')
        return deal_to_response(updated_deal)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to join deal: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to join deal"
        )


@router.post("/{deal_id}/cancel")
async def cancel_deal(deal_id: str, body: SignedActionRequest):
    """Cancel a deal (only before funding, only by creator). Requires signed request."""
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deal not found"
        )

    creator_role = deal.get('creator_role', 'seller')
    creator_id = deal['seller_id'] if creator_role == 'seller' else deal['buyer_id']
    if creator_id != body.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only deal creator can cancel"
        )

    # Verify cryptographic signature from creator
    _verify_deal_signature(deal, creator_role, "cancel", body.timestamp, body.signature, deal_id)

    if deal['status'] not in [DealStatus.PENDING.value, DealStatus.ACTIVE.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel deal in status: {deal['status']}"
        )

    deal_storage.set_deal_status(deal_id, DealStatus.CANCELLED.value)

    return {"success": True, "message": "Deal cancelled"}


@router.delete("/{deal_id}")
async def delete_deal(deal_id: str, body: SignedActionRequest):
    """
    Delete an unfunded deal (pending, active, or cancelled only).

    Permanently removes the deal from the database. Only the deal creator
    can delete. Funded deals cannot be deleted (use cancel instead).
    """
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    creator_role = deal.get('creator_role', 'seller')
    creator_id = deal['seller_id'] if creator_role == 'seller' else deal['buyer_id']
    if creator_id != body.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only deal creator can delete")

    _verify_deal_signature(deal, creator_role, "delete", body.timestamp, body.signature, deal_id)

    try:
        deal_storage.delete_deal(deal_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {"success": True, "message": "Deal deleted"}


@router.get("/{deal_id}/payout-status")
async def get_payout_status(deal_id: str):
    """
    Get payout status for a deal.

    Returns the current state of both seller (release) and buyer (refund) payouts
    without returning the full deal object.
    """
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    return {
        "deal_id": deal_id,
        "status": deal['status'],
        "seller_payout": {
            "has_invoice": bool(deal.get('seller_payout_invoice')),
            "payout_status": deal.get('payout_status'),
            "paid": deal.get('payout_status') == 'paid',
        },
        "buyer_payout": {
            "has_invoice": bool(deal.get('buyer_payout_invoice')),
            "payout_status": deal.get('buyer_payout_status'),
            "paid": deal.get('buyer_payout_status') == 'paid',
        },
    }


@router.get("/{deal_id}/recovery-info")
async def get_recovery_info(deal_id: str):
    """
    Export recovery information for independent fund recovery.

    Returns everything a user needs to recover funds without the service:
    - Fedimint escrow ID and timeout block height
    - Federation invite code (to join with own client)
    - Public keys registered in the escrow
    - Instructions for using the recovery tool

    This endpoint is public (no auth required) because the information
    is not sensitive — only the private keys (held in the user's browser)
    can authorize claims.
    """
    deal = deal_storage.get_deal_by_id(deal_id)
    if not deal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deal not found")

    escrow_id = deal.get('fedimint_escrow_id')
    if not escrow_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deal has no escrow — not yet funded"
        )

    invite_code = os.environ.get('FEDIMINT_INVITE_CODE', '')

    return {
        "deal_id": deal_id,
        "escrow_id": escrow_id,
        "timeout_block": deal.get('fedimint_timeout_block'),
        "timeout_action": deal.get('timeout_action', 'refund'),
        "federation_invite_code": invite_code,
        "buyer_pubkey_in_escrow": deal.get('buyer_escrow_pubkey'),
        "seller_pubkey_in_escrow": deal.get('seller_pubkey'),
        "amount_sats": deal.get('price_sats'),
        "status": deal.get('status'),
        "instructions": (
            "To recover funds without the service:\n"
            "1. Install escrow-recovery tool (or any Fedimint client with the escrow module)\n"
            "2. Join the federation using the invite code above\n"
            "3. Wait for the timeout block height to be reached\n"
            "4. Run: escrow-recovery --federation-invite <invite> --escrow-id <id> "
            "--private-key <your-ephemeral-key-hex> --action claim-timeout\n"
            "5. Your ephemeral private key is stored in your browser's localStorage "
            "(vault_deal_keys). Export it before clearing browser data."
        ),
    }
