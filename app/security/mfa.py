"""
ForensiX Multi-Factor Authentication (TOTP).
Handles pyotp secret generation, encrypted storage at rest,
offline base64 QR code rendering, and backup codes.
MFA is strictly mandatory for Admin and Lead roles.
"""

from __future__ import annotations

import base64
import io
import json
import secrets
from typing import List, Tuple
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from app.security.crypto import encrypt_aes_gcm, decrypt_aes_gcm


def generate_mfa_secret() -> str:
    """Generate a new standard Base32 TOTP secret."""
    return pyotp.random_base32()


def get_provisioning_uri(username: str, secret: str, issuer: str = "ForensiX Platform") -> str:
    """Construct standard otpauth TOTP provisioning URI."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_svg(provisioning_uri: str) -> str:
    """
    Render QR code locally as an SVG image encoded in a data URI.
    Operates strictly offline without external web requests.
    """
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=2,
        image_factory=SvgPathImage,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image()
    stream = io.BytesIO()
    img.save(stream)
    svg_bytes = stream.getvalue()
    b64_svg = base64.b64encode(svg_bytes).decode("ascii")
    return f"data:image/svg+xml;base64,{b64_svg}"


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify standard 6-digit TOTP token allowing 1 window drift (30s)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)


def generate_backup_codes(count: int = 8) -> Tuple[List[str], str]:
    """
    Generate recovery backup codes.
    Returns: (plain_codes_list, encrypted_codes_json).
    """
    codes = [secrets.token_hex(4).upper() for _ in range(count)]  # 8-char codes
    serialized = json.dumps(codes).encode("utf-8")
    encrypted_bytes = encrypt_aes_gcm(serialized, aad=b"mfa_backup_codes")
    return codes, encrypted_bytes.hex()


def verify_and_consume_backup_code(code: str, encrypted_codes_hex: str) -> Tuple[bool, str]:
    """Verify backup code, consume it if valid, and re-encrypt remaining codes."""
    if not encrypted_codes_hex:
        return False, ""
    try:
        encrypted_bytes = bytes.fromhex(encrypted_codes_hex)
        decrypted_bytes = decrypt_aes_gcm(encrypted_bytes, aad=b"mfa_backup_codes")
        codes: List[str] = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        return False, encrypted_codes_hex

    clean_code = code.strip().upper()
    if clean_code in codes:
        codes.remove(clean_code)
        new_serialized = json.dumps(codes).encode("utf-8")
        new_encrypted = encrypt_aes_gcm(new_serialized, aad=b"mfa_backup_codes")
        return True, new_encrypted.hex()
    return False, encrypted_codes_hex


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt Base32 TOTP secret with master AES-256 key for storage."""
    encrypted = encrypt_aes_gcm(secret.encode("utf-8"), aad=b"mfa_secret")
    return encrypted.hex()


def decrypt_mfa_secret(encrypted_hex: str) -> str:
    """Decrypt stored hex TOTP secret using master AES-256 key."""
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = decrypt_aes_gcm(encrypted_bytes, aad=b"mfa_secret")
    return decrypted.decode("utf-8")
