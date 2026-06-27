# cli-claude45-sonnet-csharp

A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 (EME wide-block mode) for the filenames.
- scrypt for key material.

---

## Installation

### Windows (Scoop)

```bash
scoop bucket add cli-claude45-sonnet-csharp https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp
scoop install cli-claude45-sonnet-csharp
```

### macOS / Linux (Homebrew)

```bash
brew tap llm-supermarket-org/cli-claude45-sonnet-csharp https://github.com/llm-supermarket-org/cli-claude45-sonnet-csharp
brew install cli-claude45-sonnet-csharp
```

### Uninstall

```bash
# Scoop (Windows)
scoop uninstall cli-claude45-sonnet-csharp
scoop bucket rm cli-claude45-sonnet-csharp

# Homebrew (macOS/Linux)
brew uninstall cli-claude45-sonnet-csharp
brew untap llm-supermarket-org/cli-claude45-sonnet-csharp
```

---

## Usage

### Encrypt a file

```bash
# Interactive password prompt (most secure)
cli-claude45-sonnet-csharp encrypt -i plaintext.txt -o encrypted_name

# Using environment variable
RCLONE_ENCRYPT_PASSWORD=mypassword cli-claude45-sonnet-csharp encrypt -i plaintext.txt

# Using --password flag (visible in shell history — not recommended)
cli-claude45-sonnet-csharp encrypt -i plaintext.txt --password mypassword

# With a custom salt (password2)
cli-claude45-sonnet-csharp encrypt -i plaintext.txt --salt mysalt

# With base64 filename encoding (default is base32)
cli-claude45-sonnet-csharp encrypt -i plaintext.txt --filename-encoding base64
```

### Decrypt a file

```bash
# Interactive password prompt
cli-claude45-sonnet-csharp decrypt -i kr9tu4e1da4u3nifdd99g9tf5o

# Decrypt a base64-encoded filename
cli-claude45-sonnet-csharp decrypt -i Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY --filename-encoding base64

# Specify output file explicitly
cli-claude45-sonnet-csharp decrypt -i kr9tu4e1da4u3nifdd99g9tf5o -o decrypted.txt
```

### Options

| Flag | Description |
|------|-------------|
| `-i`, `--input-file` | Input file path (required) |
| `-o`, `--output-file` | Output file path (optional; inferred from filename when omitted) |
| `--password` | Password (see security warning below) |
| `--salt` | Optional salt / password2 (uses rclone's built-in salt when omitted) |
| `--filename-encoding` | `base32` (default) or `base64` |

### Password security

Prefer one of these approaches over `--password`:

1. **Interactive prompt** — omit `--password`; the tool will prompt with masked input.
2. **Environment variable** — `export RCLONE_ENCRYPT_PASSWORD=mypassword` (clear with `unset RCLONE_ENCRYPT_PASSWORD` when done).

If you must use `--password`, clear it from history afterwards:
```bash
# bash
history -d $(history 1)

# PowerShell
Clear-History -Count 1 -Newest
```

---

## Building from source

```bash
dotnet publish src/RcloneEncrypt/RcloneEncrypt.csproj -c Release -r win-x64 --self-contained
```

Supported RIDs: `win-x64`, `linux-x64`, `osx-x64`, `osx-arm64`

## Running tests

```bash
dotnet test RcloneEncrypt.slnx -c Release
```
