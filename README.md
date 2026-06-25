# Voynich — standalone file recovery

Recover files encrypted by the **[Voynich](https://bdtech.app)** app on any
computer — **without the app**.

Your data is never locked in. Voynich encrypts files with standard
**AES-256-GCM**, so anyone holding the key can decrypt them with off-the-shelf
tools. [`decrypt.py`](decrypt.py) is that proof and a safety net: one short,
readable Python file with no magic. The full on-disk format is documented in
[FORMAT.md](FORMAT.md).

> This tool runs **entirely offline**. It reads your file, asks for your
> Recovery Key, and writes the decrypted result locally. It never sends anything
> anywhere — read the source and confirm.

## What you need

- The encrypted file (ends in `.enc`, or a password vault `.mdvault`).
- Your **Recovery Key** — the code from the app's *Recovery Setup*, in the form
  `XXXX-XXXX-XXXX-…`.
- **Python 3** (macOS ships it with the Xcode Command Line Tools; on Windows get
  it from [python.org](https://www.python.org/downloads/) and tick "Add Python to PATH").

## Use it (macOS / Linux)

```sh
# 1. Install the one dependency (once)
python3 -m pip install cryptography

# 2. Decrypt — you'll be asked for your Recovery Key (input is hidden,
#    so it is never written to your shell history)
python3 decrypt.py secret.txt.enc
```

The decrypted file is written next to the original as `secret.txt.enc.decrypted`,
and the script prints the original file name — rename the file back to it.

**Password vault (`.mdvault`)?** Same thing, set an output name ending in `.md`:

```sh
python3 decrypt.py passwords.mdvault -o passwords.md
```

**Windows:** open PowerShell and run the same commands with `python` instead of
`python3`.

### Other ways to pass the key

```sh
python3 decrypt.py secret.txt.enc --recovery-key XXXX-XXXX-XXXX   # on the command line
python3 decrypt.py secret.txt.enc --hex 0011223344...            # 64 hex chars (raw key)
```

## If something doesn't work

- **"Could not decrypt" / wrong key.** If the file itself is valid, the key
  doesn't match — usually because the file was encrypted on another device. Use
  that device's Recovery Key.
- **"Missing dependency".** Run `python3 -m pip install cryptography` again.

## License

[MIT](LICENSE) — use, read, and audit freely.

---

A friendlier step-by-step page (English) lives at
**https://storage.bdtech.app/file-encryption/recover/** ·
Made by [BD TECH](https://bdtech.app) · support@bdtech.app
