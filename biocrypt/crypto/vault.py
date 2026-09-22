"""Cryptographic File/Folder Vault — Bio-Crypt Lock.

True AES-256-GCM authenticated encryption (cryptography library `AESGCM`):

  * A random 256-bit vault key is derived from the user's passphrase with
    PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt).
  * Every file is sealed with its own random 12-byte nonce.
  * The original relative path is bound as GCM Additional Authenticated
    Data (AAD), so ciphertexts cannot be swapped between files undetected.
  * A manifest records original names/sizes/hashes so unlock restores the
    folder byte-for-byte; any tampering raises on decrypt.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BCL1"                    # Bio-Crypt Lock container version 1
NONCE_LEN = 12                     # bytes, standard for GCM
KEY_LEN = 32                       # 256-bit AES key
SALT_LEN = 16
PBKDF2_ITERATIONS = 600_000
MANIFEST_NAME = "manifest.bcl"

LOCKED_SUFFIX = ".bcl"             # sealed container suffix


@dataclass(frozen=True)
class VaultResult:
    sealed_paths: tuple[str, ...]
    restored_paths: tuple[str, ...]
    manifest_path: str


class VaultError(Exception):
    """Raised on tampering/corruption or wrong passphrase."""


# ---- key derivation -------------------------------------------------------

def derive_key(passphrase: str, salt: bytes,
               iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 -> 256-bit AES key (defensible in Q&A: NIST SP
    800-132 key derivation, AES-GCM authenticated encryption)."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


# ---- helpers --------------------------------------------------------------

def _encrypt_blob(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return MAGIC + nonce + ciphertext


def _decrypt_blob(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < len(MAGIC) + NONCE_LEN + 16 or not blob.startswith(MAGIC):
        raise VaultError("Not a Bio-Crypt Lock container")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
    ciphertext = blob[len(MAGIC) + NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:                      # InvalidTag or tampering
        raise VaultError(
            "Decryption failed — wrong passphrase or data tampered"
        ) from exc


def _iter_files(folder: str):
    for root, _dirs, files in os.walk(folder):
        for name in files:
            if name == MANIFEST_NAME:
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            yield full, rel.replace(os.sep, "/")


# ---- public API -----------------------------------------------------------

def seal_folder(folder: str, passphrase: str) -> VaultResult:
    """Encrypt every file inside `folder` in place.

    Each original file `X` becomes `X.bcl`; a `manifest.bcl` records the
    original tree so `unseal_folder` can restore it exactly.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise VaultError(f"Not a folder: {folder}")
    if is_sealed(folder):
        raise VaultError("Folder is already sealed")

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(passphrase, salt)

    entries = []
    sealed: list[str] = []
    for full, rel in _iter_files(folder):
        with open(full, "rb") as fh:
            plaintext = fh.read()
        blob = _encrypt_blob(key, plaintext, rel.encode("utf-8"))
        container = full + LOCKED_SUFFIX
        with open(container, "wb") as fh:
            fh.write(blob)
        os.remove(full)
        sealed.append(container)
        entries.append({
            "path": rel,
            "size": len(plaintext),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
        })

    manifest = {
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "cipher": "AES-256-GCM",
        "files": entries,
    }
    manifest_path = os.path.join(folder, MANIFEST_NAME)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    return VaultResult(tuple(sealed), (), manifest_path)


def unseal_folder(folder: str, passphrase: str) -> VaultResult:
    """Decrypt a sealed folder back to its original contents.

    Verifies the GCM tag, AAD path binding and manifest SHA-256 for every
    file; restores original filenames and removes `.bcl` shells and the
    manifest. Raises VaultError on wrong passphrase or tampering.
    """
    folder = os.path.abspath(folder)
    manifest_path = os.path.join(folder, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        raise VaultError("No manifest found — folder is not sealed")

    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    salt = bytes.fromhex(manifest["salt"])
    key = derive_key(passphrase, salt, int(manifest.get("iterations",
                                                         PBKDF2_ITERATIONS)))

    restored: list[str] = []
    for entry in manifest["files"]:
        rel = entry["path"]
        aad = rel.encode("utf-8")
        container = os.path.join(folder, *rel.split("/")) + LOCKED_SUFFIX
        if not os.path.isfile(container):
            raise VaultError(f"Missing sealed file: {container}")
        with open(container, "rb") as fh:
            blob = fh.read()

        plaintext = _decrypt_blob(key, blob, aad)

        if len(plaintext) != entry["size"]:
            raise VaultError(f"Size mismatch for {rel}")
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != entry["sha256"]:
            raise VaultError(f"Integrity check failed for {rel}")

        original = os.path.join(folder, *rel.split("/"))
        with open(original, "wb") as fh:
            fh.write(plaintext)
        os.remove(container)
        restored.append(original)

    os.remove(manifest_path)
    return VaultResult((), tuple(restored), manifest_path)


def is_sealed(folder: str) -> bool:
    return os.path.isfile(os.path.join(folder, MANIFEST_NAME))
