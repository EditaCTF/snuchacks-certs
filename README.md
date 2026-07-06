# SNUC Hacks Certificate Signer

Stamps a signature PNG onto every PDF in `pdf/`, then embeds a PKCS#7 signature with your `.p12`.

```bash
pip install -r requirements.txt
python sign.py -i pdf -o signed -p certificate.p12 -s PASSWORD -f sign.png
```

`SIG_BOX = (140, 410, 150, 50)` at the top of `sign.py` controls stamp position (PDF points, `y=0` = bottom). Adjust if the stamp lands off-target.

## Two-signatory workflow

For two stamps + one digital signature (Faculty A → Faculty B), check out the [`two-stage-signer`](../../tree/two-stage-signer) branch.

## Certificate PDFs

Download and extract into `pdf/`:

**[SNUC Hacks certificate zips (SharePoint)](https://ssneduin-my.sharepoint.com/:f:/g/personal/vijayan23110015_snuchennai_edu_in/IgCo3vYF6x7qTb_MjPGE2BeHAdNVTKnET5ejZ4VGMAZgqUk?e=D9BRde)**

## Troubleshooting

- **"Could not deserialize PKCS12 data"** → wrong `--p12-password`.
- **`pip install endesive` fails on Windows with "Visual C++ 14.0 required"** → `pip install --no-deps endesive && pip install asn1crypto oscrypto python-dateutil` (pykcs11 is optional, only for HSM/smartcard signing).