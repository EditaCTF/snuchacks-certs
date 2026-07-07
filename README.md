# SNUC Hacks Certificate Signer

Adds **Santhi Ma'am's** signature (visible stamp + PKCS#7) to certificate PDFs that already have **Padmavathi Ma'am's** stamp applied.

## Prerequisites

```bash
pip install -r requirements.txt
```

## Usage

```bash
python sign.py -i staged -o signed \
              -f santhi.png \
              -p certificate.p12 -s PASSWORD
```

Expected layout in `-i` and `-o`:

```
staged/                      signed/
├── participants/   ->       ├── participants/
├── finalists/      ->       ├── finalists/
└── volunteers/     ->       └── volunteers/
```

Each PDF in `staged/` gets Santhi's stamp + signature and lands in the matching subfolder of `signed/`.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-i, --input-dir` | yes | Folder with `participants/`, `finalists/`, `volunteers/` PDFs (already stamped by stage 1) |
| `-o, --output-dir` | yes | Output folder for signed PDFs |
| `-f, --sign-file` | yes | Santhi's signature PNG or JPG |
| `-p, --p12-file` | yes | Santhi's `.p12` / PKCS#12 signing certificate |
| `-s, --p12-password` | yes | Password for the P12 |
| `--field-name` | no | Signature field name (default: `Sig1`) |
| `--reason` | no | Override the `/Reason` string |
| `--location` | no | Override the `/Location` string |

## Stamp Position

`SIG_BOX = (130, 132, 170, 50)` at the top of `sign.py` controls the stamp position. Coordinates are in PDF points with `y=0` at the page bottom. Default places the stamp above "DR. SANTHI NATARAJAN"'s dash on the LEFT side of the SNUC Hacks '26 certificate (landscape A4, 842×595 pt). To re-calibrate for a different template, find the dash line above the faculty name in your PDF and adjust the rectangle.

## Certificate PDFs (stage 1 input)

The Padmavathi-stamped PDFs come from stage 1. The raw certificate PDFs are hosted on SharePoint:

**[SNUC Hacks certificate zips](https://ssneduin-my.sharepoint.com/:u:/g/personal/vijayan23110015_snuchennai_edu_in/IQAsJJmsMZBAS5agKPWM0wg_AZ81c7rtE6uCPwH3bbMsS94?e=DBw7qP)**

## Windows

- Activate venv with `venv\Scripts\activate` (not `source venv/bin/activate`).
- `python sign.py ...` (no `python3`).
- Single-line invocations work in cmd.exe — multi-line needs `^` instead of `\`.
- If `pip install endesive` fails with "Visual C++ 14.0 required": `pip install --no-deps endesive && pip install asn1crypto oscrypto python-dateutil` (pykcs11 is optional).

## Troubleshooting

- **"Could not deserialize PKCS12 data"** — wrong `--p12-password`.
- **"P12 file not found" / "sign image not found"** — check the `-p` / `-f` path.
- **Stamp lands in the wrong place** — adjust `SIG_BOX` at the top of `sign.py`.