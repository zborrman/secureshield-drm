"""
Content Vault — S3 storage + AES-256-GCM envelope encryption.

Encryption model (two-layer)
────────────────────────────
  Per-file key:  32 random bytes (AESGCM)
  Per-file IV:   12 random bytes (GCM nonce)
  Ciphertext:    AESGCM.encrypt(iv, plaintext, aad=None)  → ciphertext + 16-byte auth tag
  Key wrapping:  Fernet(VAULT_MASTER_KEY).encrypt(per_file_key)
                 → stores opaque token in DB; decryption verifies HMAC automatically

Master key derivation
─────────────────────
  Production : set VAULT_MASTER_KEY to a URL-safe base64-encoded 32-byte secret.
  Development: key is derived deterministically from a fixed string via SHA-256
               so tests are reproducible without env setup.

S3 configuration
────────────────
  S3_BUCKET        : bucket name (default: secureshield-vault)
  S3_REGION        : AWS region   (default: us-east-1)
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY : standard AWS credentials
  S3_ENDPOINT_URL  : optional custom endpoint for MinIO / LocalStack
"""

import base64
import hashlib
import io
import os

import boto3
from botocore.client import Config
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Configuration ─────────────────────────────────────────────────────────────

S3_BUCKET = os.getenv("S3_BUCKET", "secureshield-vault")
S3_REGION = os.getenv("S3_REGION", "us-east-1")

# Deterministic dev key — derived from a fixed string so tests need no env setup.
# In production, VAULT_MASTER_KEY must be set to a random 32-byte base64url secret.
_DEV_FERNET_KEY: bytes = base64.urlsafe_b64encode(
    hashlib.sha256(b"secureshield-dev-vault-key-v1").digest()
)

# S3 client singleton — replaced with a mock in tests (moto)
_s3 = None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    """Build a Fernet wrapper from the master key env var or the dev fallback."""
    raw = os.getenv("VAULT_MASTER_KEY", "").encode()
    if not raw:
        return Fernet(_DEV_FERNET_KEY)
    # Normalise: if already a valid 44-char base64url string decoding to 32 bytes, use as-is.
    try:
        decoded = base64.urlsafe_b64decode(raw + b"==")
        if len(decoded) == 32:
            return Fernet(raw)
    except Exception:
        pass
    # Otherwise hash to produce a canonical 32-byte key
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


def get_s3():
    """Return the module-level S3 client, creating it lazily on first call."""
    global _s3
    if _s3 is None:
        kwargs: dict = {
            "region_name": S3_REGION,
            "config": Config(signature_version="s3v4"),
        }
        endpoint = os.getenv("S3_ENDPOINT_URL")
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        _s3 = boto3.client("s3", **kwargs)
    return _s3


# ── Encryption / decryption ───────────────────────────────────────────────────

def encrypt_content(data: bytes) -> tuple[bytes, str, str]:
    """
    Encrypt `data` with AES-256-GCM.

    Returns
    -------
    ciphertext      : bytes  — encrypted blob to store in S3
    wrapped_key     : str    — Fernet-wrapped per-file AES key (store in DB)
    iv_b64          : str    — base64 GCM nonce (store in DB)
    """
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(iv, data, None)
    wrapped_key = _fernet().encrypt(aes_key).decode()
    iv_b64 = base64.b64encode(iv).decode()
    return ciphertext, wrapped_key, iv_b64


def decrypt_content(ciphertext: bytes, wrapped_key: str, iv_b64: str) -> bytes:
    """
    Reverse of `encrypt_content`.  Raises on tampered key or data.
    """
    aes_key = _fernet().decrypt(wrapped_key.encode())
    iv = base64.b64decode(iv_b64)
    return AESGCM(aes_key).decrypt(iv, ciphertext, None)


# ── S3 operations (synchronous — call via asyncio.to_thread) ─────────────────

def upload_encrypted(s3_key: str, ciphertext: bytes) -> None:
    """Upload the encrypted blob to S3 with server-side AES256 (defence-in-depth)."""
    get_s3().put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=ciphertext,
        ContentType="application/octet-stream",
        ServerSideEncryption="AES256",
    )


def download_encrypted(s3_key: str) -> bytes:
    """Download the encrypted blob from S3 and return it as bytes."""
    obj = get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
    return obj["Body"].read()


def delete_object(s3_key: str) -> None:
    """Delete an object from S3."""
    get_s3().delete_object(Bucket=S3_BUCKET, Key=s3_key)


def generate_presigned_url(s3_key: str, expires_in: int = 300) -> str:
    """
    Generate a pre-signed GET URL for an encrypted blob (admin-only, for
    verification — the blob is still AES-encrypted, so this is safe to share
    with trusted parties who know the key).
    """
    return get_s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": s3_key},
        ExpiresIn=expires_in,
    )
