# Voynich encrypted-file format (`FENC`)

Voynich encrypts every file with standard **AES-256-GCM**. There is no
proprietary container and no secret algorithm — the security rests entirely on
the key (Kerckhoffs's principle). This document fully specifies the on-disk
format so anyone can recover their data with off-the-shelf tools.
[`decrypt.py`](decrypt.py) is a reference implementation of exactly this.

## Container layout

A byte string:

```
"FENC" (4)  |  version (1)  |  nameLen (2, big-endian)  |  originalName (nameLen)  |  sealedBox
```

| Field          | Size                | Meaning                                                  |
| -------------- | ------------------- | -------------------------------------------------------- |
| magic          | 4 bytes             | ASCII `FENC`. Files are identified by this, not by extension. |
| version        | 1 byte              | `1` or `2` (see below).                                  |
| nameLen        | 2 bytes, big-endian | Length of `originalName` in bytes.                       |
| originalName   | `nameLen` bytes     | UTF-8 original file name, restored on decrypt.           |
| sealedBox      | rest of file        | AES-GCM "combined" box (below).                          |

`sealedBox` is the standard GCM combined layout:

```
nonce (12)  |  ciphertext  |  tag (16)
```

## Versions

- **Version 2** (current): the entire cleartext header — `magic | version | nameLen | originalName` — is bound as AES-GCM **associated data (AAD)**. Any tampering with the header, including the stored file name, makes decryption fail.
- **Version 1** (legacy): sealed with no associated data.

Both versions are supported by `decrypt.py`.

## The key

The key is the raw **32-byte** AES-256 key. You can provide it two ways:

- **Recovery Key** — the human-writable code from the app's *Recovery Setup*,
  e.g. `ABCD-EFGH-…`. It is **Base32** (RFC 4648 alphabet
  `A–Z 2–7`, **no padding**) of the 32 key bytes, grouped into 4-character blocks
  separated by `-`. Dashes/spaces and case are ignored on decode.
- **Hex** — the 32 key bytes as 64 hexadecimal characters.

> The Recovery Key is equivalent to the master key. Treat it like a password.

## Password vaults (`.mdvault`)

Voynich's password vault is the **same** `FENC` container; its plaintext is a
Markdown document. Decrypting a `.mdvault` therefore yields readable Markdown.
