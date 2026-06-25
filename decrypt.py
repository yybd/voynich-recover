#!/usr/bin/env python3
"""
Standalone decryptor for files encrypted by the Voynich app.

Your data is never locked to the app: files are encrypted with standard
AES-256-GCM, so anyone holding the key can recover them with off-the-shelf
tools. This script is that proof — and a safety net.

On-disk format (see FORMAT.md):

    "FENC" (4)  | version (1)  | nameLen (2, big-endian)  | originalName (nameLen)  | sealedBox

where sealedBox is the standard GCM "combined" layout:

    nonce (12)  | ciphertext  | tag (16)

Version 2 files authenticate the cleartext header (everything before the sealed
box) as AES-GCM associated data; version 1 files do not. Both are supported.

The key is the raw 32-byte master key. You can supply it as your Recovery Key
(the Base32 code from Recovery Setup) or as 64 hex characters. Password
documents (.mdvault) use the same format; decrypting one yields its Markdown.

If you give no key on the command line, the script prompts for the Recovery Key
with the input hidden. That is the recommended path: the Recovery Key is
equivalent to the master key, so typing it as an argument would leave it in your
shell history — the prompt keeps it out.

Requires:  pip install cryptography

Examples:
    python3 decrypt.py secret.txt            # prompts for the Recovery Key (hidden)
    python3 decrypt.py secret.txt --recovery-key ABCD-EFGH-...
    python3 decrypt.py passwords.mdvault -k ABCD-... -o passwords.md
    python3 decrypt.py secret.txt --hex 0011223344...   # 64 hex chars
"""
import argparse
import base64
import getpass
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency. Install it with:\n    pip install cryptography")

MAGIC = b"FENC"
SUPPORTED_VERSIONS = (1, 2)
NONCE_LEN = 12


def key_from_recovery_code(code: str) -> bytes:
    """Decode a Recovery Key (Base32, dash/space separated) into the 32-byte key."""
    cleaned = code.strip().upper().replace("-", "").replace(" ", "")
    cleaned += "=" * (-len(cleaned) % 8)  # pad to a multiple of 8 for b32decode
    key = base64.b32decode(cleaned)
    if len(key) != 32:
        raise ValueError(f"recovery key decoded to {len(key)} bytes, expected 32")
    return key


def key_from_hex(hexstr: str) -> bytes:
    key = bytes.fromhex(hexstr.strip())
    if len(key) != 32:
        raise ValueError(f"hex key is {len(key)} bytes, expected 32")
    return key


def decrypt(blob: bytes, key: bytes) -> tuple[str, bytes]:
    """Parse a FENC container and return (original_name, plaintext)."""
    if blob[:4] != MAGIC:
        raise ValueError("not a FENC file (missing magic) — is it already decrypted?")
    version = blob[4]
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported format version {version}")
    name_len = int.from_bytes(blob[5:7], "big")
    offset = 7 + name_len
    original_name = blob[7:offset].decode("utf-8", errors="replace")
    header = blob[:offset]                     # magic | version | nameLen | name
    body = blob[offset:]                       # nonce | ciphertext | tag
    nonce, ct_and_tag = body[:NONCE_LEN], body[NONCE_LEN:]
    # v2 authenticates the header as associated data; v1 used none.
    aad = header if version >= 2 else None
    plaintext = AESGCM(key).decrypt(nonce, ct_and_tag, aad)  # tag is appended to ct
    return original_name, plaintext


def main() -> None:
    p = argparse.ArgumentParser(
        description="Decrypt a File Encryption (.FENC) file with your key.")
    p.add_argument("file", type=Path, help="the encrypted file to decrypt")
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--recovery-key", "-k",
                     help="your Recovery Key (Base32, e.g. ABCD-EFGH-...). "
                          "Omit to be prompted for it with the input hidden.")
    src.add_argument("--hex", help="the raw 32-byte key as 64 hex characters")
    p.add_argument("--out", "-o", type=Path,
                   help="output file (default: <file>.decrypted)")
    args = p.parse_args()

    # Resolve the key. With no flag, prompt for the Recovery Key with the input
    # hidden — it is equivalent to the master key, so this keeps it out of your
    # shell history.
    try:
        if args.recovery_key:
            key = key_from_recovery_code(args.recovery_key)
        elif args.hex:
            key = key_from_hex(args.hex)
        else:
            entered = getpass.getpass("Paste your Recovery Key (input hidden): ")
            if not entered.strip():
                sys.exit("No key entered.")
            key = key_from_recovery_code(entered)
    except Exception as e:
        sys.exit(f"Bad key: {e}")

    try:
        blob = args.file.read_bytes()
    except OSError as e:
        sys.exit(f"Can't read {args.file}: {e}")

    try:
        original_name, plaintext = decrypt(blob, key)
    except Exception as e:
        sys.exit(f"Could not decrypt: {e}\n"
                 "If the file itself is valid, the key is wrong — it may have "
                 "been encrypted on another device (restore that device's key).")

    out = args.out or args.file.with_name(args.file.name + ".decrypted")
    try:
        out.write_bytes(plaintext)
    except OSError as e:
        sys.exit(f"Can't write {out}: {e}")

    print(f"Decrypted  {args.file}  ->  {out}  ({len(plaintext)} bytes)")
    print(f"Original name recorded in header: {original_name}")


if __name__ == "__main__":
    main()
