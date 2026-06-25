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
equivalent to the master key, so passing it as an argument would leave it both in
your shell history and visible to other local users via the process list (ps).

This tool is fully offline: it reads a file, decrypts in memory, and writes the
result. It makes no network connections and runs no other programs.

Note: the decrypted output is PLAINTEXT on disk. Decrypting a .mdvault writes its
passwords in the clear — delete the output when you're done, and prefer a private
machine. The output file is created owner-only (mode 0600), and an existing file
is never overwritten unless you pass --force.

Requires:  pip install cryptography

Examples:
    python3 decrypt.py secret.txt            # prompts for the Recovery Key (hidden)
    python3 decrypt.py secret.txt --recovery-key ABCD-EFGH-...
    python3 decrypt.py passwords.mdvault -k ABCD-... -o passwords.md
    python3 decrypt.py secret.txt --hex 0011223344...   # 64 hex chars
    python3 decrypt.py secret.txt -o -        # write plaintext to stdout
"""
import argparse
import base64
import getpass
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    sys.exit("Missing dependency. Install it with:\n    pip install cryptography")

MAGIC = b"FENC"
SUPPORTED_VERSIONS = (1, 2)
NONCE_LEN = 12
TAG_LEN = 16


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
    """Parse a FENC container and return (original_name, plaintext).

    Raises ValueError for a malformed or truncated container, and cryptography's
    InvalidTag when the key is wrong or the file was tampered with.
    """
    if len(blob) < 7 or blob[:4] != MAGIC:
        raise ValueError("not a valid FENC file (bad magic, or a truncated header) "
                         "— is it perhaps already decrypted?")
    version = blob[4]
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported format version {version}")
    name_len = int.from_bytes(blob[5:7], "big")
    offset = 7 + name_len
    if len(blob) < offset + NONCE_LEN + TAG_LEN:
        raise ValueError("the file is truncated (shorter than the format requires)")
    original_name = blob[7:offset].decode("utf-8", errors="replace")
    header = blob[:offset]                     # magic | version | nameLen | name
    body = blob[offset:]                       # nonce | ciphertext | tag
    nonce, ct_and_tag = body[:NONCE_LEN], body[NONCE_LEN:]
    # v2 authenticates the header as associated data; v1 used none.
    aad = header if version >= 2 else None
    plaintext = AESGCM(key).decrypt(nonce, ct_and_tag, aad)  # tag is appended to ct
    return original_name, plaintext


def safe_name(name: str) -> str:
    """Render a header-supplied name for display. In v1 files the name is
    attacker-controllable, so escape any non-printable bytes rather than letting
    terminal escape sequences through when we print it."""
    if not name:
        return "(none)"
    return name if name.isprintable() else repr(name)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Decrypt a Voynich (.FENC) file with your key.")
    p.add_argument("file", type=Path, help="the encrypted file to decrypt")
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--recovery-key", "-k",
                     help="your Recovery Key (Base32, e.g. ABCD-EFGH-...). "
                          "Omit to be prompted for it with the input hidden.")
    src.add_argument("--hex", help="the raw 32-byte key as 64 hex characters")
    p.add_argument("--out", "-o", type=Path,
                   help="output file, or '-' for stdout (default: <file>.decrypted)")
    p.add_argument("--force", "-f", action="store_true",
                   help="overwrite the output file if it already exists")
    args = p.parse_args()

    # Resolve the key. With no flag, prompt for the Recovery Key with the input
    # hidden — it is equivalent to the master key, so this keeps it out of your
    # shell history and off the process list.
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
    except InvalidTag:
        sys.exit("Could not decrypt: wrong key, or the file was modified.\n"
                 "Most often the file was encrypted on another device — restore "
                 "that device's key in Recovery Setup and use it here.")
    except ValueError as e:
        sys.exit(f"Could not read this file: {e}")

    to_stdout = str(args.out) == "-"
    out = None if to_stdout else (args.out or args.file.with_name(args.file.name + ".decrypted"))

    if to_stdout:
        try:
            sys.stdout.buffer.write(plaintext)
            sys.stdout.buffer.flush()
        except OSError as e:
            sys.exit(f"Can't write to stdout: {e}")
    else:
        # O_EXCL makes "don't overwrite" atomic (no TOCTOU); 0o600 keeps the
        # plaintext owner-only.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | (0 if args.force else os.O_EXCL)
        try:
            fd = os.open(out, flags, 0o600)
        except FileExistsError:
            sys.exit(f"Refusing to overwrite existing {out} (use --force to overwrite).")
        except OSError as e:
            sys.exit(f"Can't write {out}: {e}")
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, 0o600)  # tighten perms even when overwriting (--force)
            except OSError:
                pass
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(plaintext)
        except OSError as e:
            sys.exit(f"Can't write {out}: {e}")

    # Informational output goes to stderr so stdout stays clean for piping.
    dest = "stdout" if to_stdout else str(out)
    print(f"Decrypted {args.file} -> {dest} ({len(plaintext)} bytes)", file=sys.stderr)
    print(f"Original name recorded in header: {safe_name(original_name)}", file=sys.stderr)


if __name__ == "__main__":
    main()
