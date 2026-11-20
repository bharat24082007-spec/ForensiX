"""
ForensiX Cryptographic Utilities.
Handles master key generation, AES-256-GCM encryption/decryption,
and Ed25519 digital signature key-pair generation.
Master key is strictly stored outside data/vault/ with 0600 permissions.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Tuple
import argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def get_master_key(key_path: Path | None = None) -> bytes:
    """
    Retrieve or create the master AES-256 key (32 bytes).
    Strictly placed in data/keys/master.key (outside data/vault/).
    Sets POSIX 0600 permissions where supported.
    """
    if key_path is None:
        key_path = Path("data/keys/master.key")

    key_path = Path(key_path).resolve()
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.is_file():
        with open(key_path, "rb") as f:
            key = f.read()
            if len(key) != 32:
                raise ValueError("Corrupted master key: length must be exactly 32 bytes.")
            return key

    # Generate new random 32-byte key
    key = os.urandom(32)
    with open(key_path, "wb") as f:
        f.write(key)

    try:
        os.chmod(key_path, 0o600)
    except (OSError, NotImplementedError):
        pass

    return key


def encrypt_aes_gcm(plaintext: bytes, aad: bytes = b"", master_key: bytes | None = None) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns: 12-byte nonce + ciphertext with appended 16-byte authentication tag.
    """
    key = master_key or get_master_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit unique nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_aes_gcm(encrypted_bundle: bytes, aad: bytes = b"", master_key: bytes | None = None) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext bundle.
    Expects: 12-byte nonce followed by ciphertext and authentication tag.
    """
    if len(encrypted_bundle) < 28:
        raise ValueError("Invalid AES-GCM bundle: payload too short.")

    key = master_key or get_master_key()
    aesgcm = AESGCM(key)
    nonce = encrypted_bundle[:12]
    ciphertext = encrypted_bundle[12:]
    return aesgcm.decrypt(nonce, ciphertext, aad)


def encrypt_file_aes_gcm_chunked(
    src_path: Path,
    dst_path: Path,
    master_key: bytes | None = None,
    chunk_size: int = 1024 * 1024,
) -> None:
    """
    Encrypt a file in 1 MiB chunks using AES-256-GCM.
    Each chunk receives a unique 96-bit nonce and chunk index as AAD.
    """
    key = master_key or get_master_key()
    aesgcm = AESGCM(key)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        # Write 12-byte header: Magic 'FVAU' + Version (1) + Chunk Size
        fout.write(b"FVAU")
        fout.write((1).to_bytes(4, "big"))
        fout.write(chunk_size.to_bytes(4, "big"))

        chunk_index = 0
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(12)
            aad = chunk_index.to_bytes(8, "big")
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, aad)

            fout.write(len(encrypted_chunk).to_bytes(4, "big"))
            fout.write(nonce)
            fout.write(encrypted_chunk)
            chunk_index += 1


def decrypt_file_aes_gcm_chunked(
    src_path: Path,
    dst_path: Path,
    master_key: bytes | None = None,
) -> None:
    """Decrypt a chunked AES-256-GCM vault file and write plaintext to dst_path."""
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "wb") as fout:
        for chunk in decrypt_stream_aes_gcm_chunked(src_path, master_key=master_key):
            fout.write(chunk)


def decrypt_stream_aes_gcm_chunked(
    src_path: Path,
    master_key: bytes | None = None,
):
    """Generator yielding decrypted plaintext chunks from an encrypted vault file."""
    key = master_key or get_master_key()
    aesgcm = AESGCM(key)

    with open(src_path, "rb") as fin:
        header = fin.read(12)
        if len(header) < 12 or header[:4] != b"FVAU":
            raise ValueError("Corrupted vault file: invalid magic header.")

        version = int.from_bytes(header[4:8], "big")
        if version != 1:
            raise ValueError(f"Unsupported vault version: {version}")

        chunk_index = 0
        while True:
            len_bytes = fin.read(4)
            if not len_bytes:
                break
            chunk_len = int.from_bytes(len_bytes, "big")
            nonce = fin.read(12)
            if len(nonce) < 12:
                raise ValueError("Corrupted vault file: truncated nonce.")

            encrypted_chunk = fin.read(chunk_len)
            if len(encrypted_chunk) < chunk_len:
                raise ValueError("Corrupted vault file: truncated chunk data.")

            aad = chunk_index.to_bytes(8, "big")
            plaintext = aesgcm.decrypt(nonce, encrypted_chunk, aad)
            yield plaintext
            chunk_index += 1


def generate_ed25519_keypair(master_key: bytes | None = None) -> Tuple[str, str]:
    """
    Generate an Ed25519 signing keypair for forensic reporting.
    Returns: (public_key_hex, encrypted_private_key_hex).
    Private key is AES-256-GCM encrypted before returning.
    """
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    encrypted_priv = encrypt_aes_gcm(priv_bytes, aad=b"ed25519_priv_key", master_key=master_key)

    return pub_bytes.hex(), encrypted_priv.hex()


def load_ed25519_private_key(encrypted_priv_hex: str, master_key: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    """Decrypt and load an Ed25519 private key from its encrypted hex representation."""
    encrypted_bytes = bytes.fromhex(encrypted_priv_hex)
    decrypted_priv_bytes = decrypt_aes_gcm(encrypted_bytes, aad=b"ed25519_priv_key", master_key=master_key)
    return ed25519.Ed25519PrivateKey.from_private_bytes(decrypted_priv_bytes)


def derive_sub_key(master_key: bytes, context_label: bytes, length: int = 32) -> bytes:
    """
    Derive an isolated cryptographic subkey from master key using HKDF-SHA256.
    Ensures cryptographic domain separation between vault data, custody HMACs, and export wraps.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"forensix-subkeys-salt-v1",
        info=context_label,
    )
    return hkdf.derive(master_key)


def compute_custody_hmac(entry_hash_hex: str, master_key: bytes | None = None) -> str:
    """
    Compute HMAC-SHA256 over an entry_hash using the custody HMAC subkey derived via HKDF (C3).
    Stops anyone with only database access from recomputing a valid custody chain without the master key.
    """
    m_key = master_key or get_master_key()
    hmac_key = derive_sub_key(m_key, b"forensix-custody-hmac")
    return hmac.new(hmac_key, entry_hash_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def export_encrypted_master_key(passphrase: str, master_key: bytes | None = None) -> bytes:
    """
    Export master key encrypted with an Admin-chosen passphrase via Argon2id + AES-256-GCM (C2).
    Format: b"FXMK" (4B magic) + 16B salt + 12B nonce + ciphertext with 16B GCM tag.
    """
    if len(passphrase.strip()) < 12:
        raise ValueError("Master key export passphrase must be at least 12 characters.")

    m_key = master_key or get_master_key()
    salt = os.urandom(16)
    derived_wrap_key = argon2.low_level.hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )

    aesgcm = AESGCM(derived_wrap_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, m_key, b"forensix-master-key-export-v1")
    return b"FXMK" + salt + nonce + ciphertext


def decrypt_exported_master_key(enc_payload: bytes, passphrase: str) -> bytes:
    """
    Decrypt an exported master key using the Admin passphrase.
    Returns 32-byte master key, or raises ValueError on failure.
    """
    if len(enc_payload) < 4 + 16 + 12 + 16:  # Magic + salt + nonce + tag
        raise ValueError("Invalid encrypted master key bundle: payload too short.")

    if not enc_payload.startswith(b"FXMK"):
        raise ValueError("Invalid master key file: unrecognized header magic bytes.")

    salt = enc_payload[4:20]
    nonce = enc_payload[20:32]
    ciphertext = enc_payload[32:]

    derived_wrap_key = argon2.low_level.hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )

    try:
        aesgcm = AESGCM(derived_wrap_key)
        master_key = aesgcm.decrypt(nonce, ciphertext, b"forensix-master-key-export-v1")
        if len(master_key) != 32:
            raise ValueError("Decrypted master key has invalid length.")
        return master_key
    except Exception as e:
        raise ValueError("Failed to decrypt master key: incorrect passphrase or corrupted file.") from e
