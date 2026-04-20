# SNUC Hacks Certificate Signer

Signs participant, finalist, and volunteer PDFs with a visible stamp image and PKCS#7 cryptographic signature.


## Prerequisites

```bash
pip install -r requirements.txt
```


## Usage

```bash
python sign.py -i ./pdf -o ./signed \
              -p certificate.p12 \
              -s PASSWORD \
              -f sign.png
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `-i, --input-dir` | Directory containing PDF subfolders (`participants/`, `finalists/`, `volunteers/`) |
| `-o, --output-dir` | Output directory for signed PDFs |
| `-p, --p12-file` | Path to P12/PKCS12 signing certificate |
| `-s, --p12-password` | Password for P12 certificate |
| `-f, --sign-file` | Path to `sign.png` (visible stamp image) |

### Optional

`--platform linux|darwin|windows` — Force platform (auto-detected by default)

## File Requirements

**sign.png**
- PNG format, recommended ~400x120 px
- Positioned via `SIG_BOX` coordinates

**certificate.p12**
- PKCS#12 format signing certificate
- Must have a password (passed via `--p12-password`)
- Contains private key + certificate + CA chain

## Output Structure

```
<output-dir>/
├── participants/   (697 PDFs)
├── finalists/      (97 PDFs)
└── volunteers/      (27 PDFs)
```

## SIG_BOX — Stamp Position

Coordinates `(x, y, width, height)` in PDF points. `y=0` = bottom of page.

Default: `SIG_BOX = (140, 410, 150, 50)`


To adjust, edit the `SIG_BOX` constant at the top of `sign.py`.

PDF page dimensions (landscape A4): ~842 pts × ~595 pts

## Dependencies

- **pymupdf** — image stamping
- **pypdf** — PDF manipulation
- **endesive** — CMS/PKCS#7 cryptographic signing
- **pillow** — image dimension checking
- **cryptography** — P12 certificate loading

## Troubleshooting

**"Could not deserialize PKCS12 data"**
→ Wrong `--p12-password`. Check for extra spaces/newlines.


**"sign.png not found"**
→ Verify `-f` path is correct and the file exists.


**"SIG_BOX position is wrong"**
→ Adjust `SIG_BOX` tuple at the top of `sign.py` and re-run.
