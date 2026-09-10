"""
Ed25519 Asymmetric Cryptographic Signing and Verification for VisionTrust.
Enforces:
- Secure key generation and storage (never returning private keys via API)
- Deterministic payload formatting for model metadata signatures
- Evidence record signatures linking input_hash, model_hash, and output_hash
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.config import get_settings

KEYS_DIR = Path(".keys").resolve()


def ensure_keys_dir() -> Path:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    return KEYS_DIR


def get_or_create_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """
    Load or generate an Ed25519 keypair.
    The private key is stored securely in .keys/ and NEVER exposed through APIs.
    Returns (private_key_object, public_key_hex).
    """
    settings = get_settings()
    priv_path = Path(settings.private_key_path) if settings.private_key_path else KEYS_DIR / "ed25519_private.pem"
    pub_path = Path(settings.public_key_path) if settings.public_key_path else KEYS_DIR / "ed25519_public.pem"

    if priv_path.exists() and pub_path.exists():
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Configured key is not an Ed25519 private key.")
    else:
        ensure_keys_dir()
        private_key = ed25519.Ed25519PrivateKey.generate()
        # Write private key in standard PKCS#8 PEM format
        with open(priv_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        public_key = private_key.public_key()
        with open(pub_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    public_key = private_key.public_key()
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, pub_raw.hex()


def format_model_metadata_payload(
    model_id: str,
    version_tag: str,
    model_hash: str,
    associated_dataset_version: str | None,
    approval_status: str,
) -> bytes:
    """Canonical UTF-8 byte serialization for model metadata signing."""
    parts = [
        model_id,
        version_tag,
        model_hash,
        associated_dataset_version or "",
        approval_status,
    ]
    return "|".join(parts).encode("utf-8")


def sign_model_metadata(
    private_key: ed25519.Ed25519PrivateKey,
    model_id: str,
    version_tag: str,
    model_hash: str,
    associated_dataset_version: str | None,
    approval_status: str,
) -> str:
    """Sign canonical model metadata using Ed25519 private key and return hex signature."""
    payload = format_model_metadata_payload(
        model_id, version_tag, model_hash, associated_dataset_version, approval_status
    )
    sig_bytes = private_key.sign(payload)
    return sig_bytes.hex()


def verify_model_metadata(
    public_key_hex: str,
    model_id: str,
    version_tag: str,
    model_hash: str,
    associated_dataset_version: str | None,
    approval_status: str,
    signature_hex: str,
) -> bool:
    """Verify Ed25519 signature over canonical model metadata."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        payload = format_model_metadata_payload(
            model_id, version_tag, model_hash, associated_dataset_version, approval_status
        )
        public_key.verify(sig_bytes, payload)
        return True
    except (ValueError, InvalidSignature):
        return False


def format_evidence_payload(input_hash: str, model_hash: str, output_hash: str) -> bytes:
    """Canonical payload for inference evidence record signing."""
    return f"{input_hash}|{model_hash}|{output_hash}".encode("utf-8")


def sign_evidence_record(
    private_key: ed25519.Ed25519PrivateKey,
    input_hash: str,
    model_hash: str,
    output_hash: str,
) -> str:
    """Sign inference evidence record linking input, model, and output."""
    payload = format_evidence_payload(input_hash, model_hash, output_hash)
    return private_key.sign(payload).hex()


def verify_evidence_record(
    public_key_hex: str,
    input_hash: str,
    model_hash: str,
    output_hash: str,
    signature_hex: str,
) -> bool:
    """Verify evidence record signature."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        payload = format_evidence_payload(input_hash, model_hash, output_hash)
        public_key.verify(sig_bytes, payload)
        return True
    except (ValueError, InvalidSignature):
        return False
