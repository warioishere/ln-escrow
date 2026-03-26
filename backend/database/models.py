"""
SQLAlchemy models for escrow system — Fedimint + Lightning.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, BigInteger, Boolean, DateTime,
    Text, Index,
)
from sqlalchemy.orm import declarative_base
import enum

Base = declarative_base()


class DealStatus(str, enum.Enum):
    """Deal status for web app flow"""
    PENDING = "pending"      # Creator made deal, waiting for counterparty
    ACTIVE = "active"        # Buyer joined, waiting for funding
    FUNDED = "funded"        # Payment received
    SHIPPED = "shipped"      # Seller marked as shipped
    RELEASED = "released"    # Buyer confirmed release, waiting for seller to collect
    RELEASING = "releasing"  # Write-ahead: release intent recorded
    REFUNDING = "refunding"  # Write-ahead: refund intent recorded
    COMPLETED = "completed"  # Buyer confirmed, funds released
    REFUNDED = "refunded"    # Refund issued
    DISPUTED = "disputed"    # Dispute raised
    CANCELLED = "cancelled"  # Deal cancelled
    EXPIRED = "expired"      # Timeout expired


class DealModel(Base):
    """
    Deal model for web app

    Represents a trade deal between buyer and seller.
    Fedimint holds the escrow.
    """
    __tablename__ = 'deals'

    # Primary key
    deal_id = Column(String(36), primary_key=True)

    # Shareable link token (unique, used in URLs)
    deal_link_token = Column(String(32), unique=True, nullable=False, index=True)

    # Who created the deal ('buyer' or 'seller')
    creator_role = Column(String(10), nullable=False, default='seller')

    # Participants (web user IDs from localStorage)
    seller_id = Column(String(100), nullable=True, index=True)
    seller_name = Column(String(100), nullable=True)
    buyer_id = Column(String(100), nullable=True, index=True)
    buyer_name = Column(String(100), nullable=True)

    # Deal info
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    price_sats = Column(BigInteger, nullable=False)

    # Contract terms
    timeout_hours = Column(Integer, nullable=False, default=72)
    timeout_action = Column(String(20), nullable=False, default='refund')  # refund, release, split, arbiter
    requires_tracking = Column(Boolean, nullable=False, default=False)

    # Status
    status = Column(String(20), nullable=False, default='pending', index=True)

    # Shipping info
    tracking_carrier = Column(String(50), nullable=True)
    tracking_number = Column(String(100), nullable=True)
    shipping_notes = Column(Text, nullable=True)

    invoice_amount_sats = Column(BigInteger, nullable=True)
    service_fee_sats = Column(Integer, nullable=True)
    chain_fee_budget_sats = Column(Integer, nullable=True)

    # Lightning invoice
    ln_payment_hash = Column(String(64), nullable=True, index=True)
    ln_invoice = Column(Text, nullable=True)
    ln_operation_id = Column(String(100), nullable=True)  # fedimint-cli await-invoice operation ID

    # Public keys (from browser / LNURL-auth) — used for signature verification
    buyer_pubkey = Column(String(66), nullable=True)
    seller_pubkey = Column(String(66), nullable=True)

    # LNURL-auth - Linking pubkeys (wallet identity)
    buyer_linking_pubkey = Column(String(66), nullable=True)
    seller_linking_pubkey = Column(String(66), nullable=True)

    # LNURL-auth - Verified flags
    buyer_auth_verified = Column(Boolean, nullable=True, default=False)
    seller_auth_verified = Column(Boolean, nullable=True, default=False)

    # LNURL-auth - Stored signatures for key recovery
    buyer_auth_signature = Column(Text, nullable=True)
    seller_auth_signature = Column(Text, nullable=True)

    # Payout invoice - LN invoice or Lightning Address for seller payout on release
    seller_payout_invoice = Column(Text, nullable=True)

    # Payout status tracking (null=no payout attempted, pending, paid, failed)
    payout_status = Column(String(20), nullable=True)
    payout_fee_sat = Column(Integer, nullable=True)

    # Buyer refund payout - LN invoice or Lightning Address for buyer payout on refund
    buyer_payout_invoice = Column(Text, nullable=True)
    buyer_payout_status = Column(String(20), nullable=True)
    buyer_payout_fee_sat = Column(Integer, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    buyer_started_at = Column(DateTime, nullable=True)  # When buyer opened join link
    buyer_joined_at = Column(DateTime, nullable=True)   # When buyer completed auth
    funded_at = Column(DateTime, nullable=True)
    shipped_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)

    # Write-ahead broadcast tracking (escrow_id stored here in Fedimint mode)
    release_txid = Column(String(100), nullable=True)
    refund_txid = Column(String(100), nullable=True)

    # Fedimint secret_code hash for non-custodial release verification
    # The plaintext secret_code is delivered once to buyer's browser and then nulled.
    # Only the SHA-256 hash is kept for release authorization.
    fedimint_secret_code_hash = Column(String(64), nullable=True)

    # Legacy columns — still NOT NULL in production DB, kept to satisfy constraint
    signing_phase = Column(String(30), nullable=False, default='initial', server_default='initial')
    invoice_bolt11 = Column(Text, nullable=True)

    # Recovery contact (optional, for admin to verify identity if keys lost)
    buyer_recovery_contact = Column(String(200), nullable=True)
    seller_recovery_contact = Column(String(200), nullable=True)

    # Fedimint escrow
    fedimint_escrow_id = Column(String(100), nullable=True, index=True)
    # NOTE: fedimint_secret_code column REMOVED — non-custodial invariant.
    # Plaintext secret_code is NEVER stored in DB. Only the hash is kept.
    # See _payout.py:_secret_code_cache for the in-memory delivery mechanism.
    fedimint_timeout_block = Column(Integer, nullable=True) # Bitcoin block height for timeout

    # Non-custodial: buyer's ephemeral key used as buyer_pubkey in Fedimint escrow
    buyer_escrow_pubkey = Column(String(66), nullable=True)
    # Non-custodial: pre-signed SHA256("timeout") from buyer's ephemeral key (hex)
    buyer_timeout_signature = Column(Text, nullable=True)
    # Non-custodial: pre-signed SHA256("timeout") from seller's ephemeral key (hex)
    # Used for timeout_action="release" (seller gets paid on timeout)
    seller_timeout_signature = Column(Text, nullable=True)
    # Non-custodial: AES-256-GCM encrypted secret_code, stored at funding time.
    # Only the buyer's ephemeral key (derived from wallet signature) can decrypt.
    # Server cannot decrypt — ephemeral key never stored server-side.
    buyer_encrypted_vault = Column(Text, nullable=True)

    # Dispute info
    disputed_at = Column(DateTime, nullable=True)
    disputed_by = Column(String(100), nullable=True)  # user_id of who opened dispute
    dispute_reason = Column(Text, nullable=True)

    # Indexes
    __table_args__ = (
        Index('ix_deals_status_created', 'status', 'created_at'),
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary"""
        return {
            'deal_id': self.deal_id,
            'deal_link_token': self.deal_link_token,
            'creator_role': self.creator_role,
            'seller_id': self.seller_id,
            'seller_name': self.seller_name,
            'buyer_id': self.buyer_id,
            'buyer_name': self.buyer_name,
            'title': self.title,
            'description': self.description,
            'price_sats': self.price_sats,
            'timeout_hours': self.timeout_hours,
            'timeout_action': self.timeout_action,
            'requires_tracking': self.requires_tracking,
            'status': self.status,
            'tracking_carrier': self.tracking_carrier,
            'tracking_number': self.tracking_number,
            'shipping_notes': self.shipping_notes,
            'invoice_amount_sats': self.invoice_amount_sats,
            'service_fee_sats': self.service_fee_sats,
            'chain_fee_budget_sats': self.chain_fee_budget_sats,
            'ln_payment_hash': self.ln_payment_hash,
            'ln_invoice': self.ln_invoice,
            'ln_operation_id': self.ln_operation_id,
            'buyer_pubkey': self.buyer_pubkey,
            'seller_pubkey': self.seller_pubkey,
            'buyer_linking_pubkey': self.buyer_linking_pubkey,
            'seller_linking_pubkey': self.seller_linking_pubkey,
            'buyer_auth_verified': self.buyer_auth_verified,
            'seller_auth_verified': self.seller_auth_verified,
            'seller_payout_invoice': self.seller_payout_invoice,
            'payout_status': self.payout_status,
            'payout_fee_sat': self.payout_fee_sat,
            'buyer_payout_invoice': self.buyer_payout_invoice,
            'buyer_payout_status': self.buyer_payout_status,
            'buyer_payout_fee_sat': self.buyer_payout_fee_sat,
            # Timestamps
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'buyer_started_at': self.buyer_started_at.isoformat() if self.buyer_started_at else None,
            'buyer_joined_at': self.buyer_joined_at.isoformat() if self.buyer_joined_at else None,
            'funded_at': self.funded_at.isoformat() if self.funded_at else None,
            'shipped_at': self.shipped_at.isoformat() if self.shipped_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            # Write-ahead tracking
            'release_txid': self.release_txid,
            'refund_txid': self.refund_txid,
            # Fedimint escrow
            'fedimint_escrow_id': self.fedimint_escrow_id,
            'fedimint_timeout_block': self.fedimint_timeout_block,
            'buyer_escrow_pubkey': self.buyer_escrow_pubkey,
            'buyer_timeout_signature': self.buyer_timeout_signature,
            'seller_timeout_signature': self.seller_timeout_signature,
            'buyer_encrypted_vault': self.buyer_encrypted_vault,
            'buyer_auth_signature': self.buyer_auth_signature,
            'seller_auth_signature': self.seller_auth_signature,
            # Dispute info
            'disputed_at': self.disputed_at.isoformat() if self.disputed_at else None,
            'disputed_by': self.disputed_by,
            'dispute_reason': self.dispute_reason,
            # Recovery contacts
            'buyer_recovery_contact': self.buyer_recovery_contact,
            'seller_recovery_contact': self.seller_recovery_contact,
        }

    def __repr__(self):
        return f"<Deal {self.deal_id[:8]} status={self.status} price={self.price_sats}>"


class WebhookModel(Base):
    """Registered webhook endpoint for deal event notifications."""
    __tablename__ = 'webhooks'

    id = Column(String(16), primary_key=True)
    url = Column(String(500), nullable=False)
    secret = Column(String(200), nullable=True)
    events = Column(Text, nullable=False, default='["*"]')  # JSON list
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self, redact_secret: bool = True) -> dict:
        import json
        return {
            'id': self.id,
            'url': self.url,
            'secret': '***' if redact_secret and self.secret else self.secret,
            'events': json.loads(self.events) if self.events else ['*'],
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Webhook {self.id} url={self.url}>"


