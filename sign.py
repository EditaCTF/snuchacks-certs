#!/usr/bin/env python3
"""Sign SNUC Hacks certificates with digital signature + visible stamp.


Uses PyMuPDF to render sign.png visually on each PDF page,
then pypdf + endesive to embed the cryptographic signature.


Requirements:
    pip install -r requirements.txt

Usage:
    python sign.py --input-dir ./pdf --output-dir ./signed \
                   --p12-file certificate.p12 --p12-password SECRET \
                   --sign-file sign.png
"""

import argparse
import hashlib
import io
import os
import platform
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# SIG_BOX — stamp position in PDF points (x, y, width, height)
# y=0 is BOTTOM of page in PDF coordinates
# ─────────────────────────────────────────────────────────────────────────────


SIG_BOX = (140, 410, 150, 50)


# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS — requires: pip install -r requirements.txt
# ─────────────────────────────────────────────────────────────────────────────


try:
    import fitz  # PyMuPDF
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        NumberObject,
        ByteStringObject,
    )
    from endesive import signer as endesive_signer
    from cryptography.hazmat.primitives.serialization import pkcs12
    from PIL import Image
except ImportError as e:
    print(f"Error: missing dependency - {e}", file=sys.stderr)
    print("Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# P12 LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_p12(cert_path: Path, password: str):
    with open(cert_path, "rb") as f:
        p12_data = f.read()
    private_key, certificate, other_certs = pkcs12.load_key_and_certificates(
        p12_data, password.encode("utf-8")
    )
    return private_key, certificate, other_certs or []


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTOGRAPHIC SIGNING
# ─────────────────────────────────────────────────────────────────────────────

def create_signature_annotation(x: float, y: float, w: float, h: float, field_name: str):
    annot = DictionaryObject()
    annot[NameObject("/Type")] = NameObject("/Annot")
    annot[NameObject("/Subtype")] = NameObject("/Widget")
    annot[NameObject("/Rect")] = ArrayObject([
        NumberObject(x), NumberObject(y),
        NumberObject(x + w), NumberObject(y + h),
    ])
    annot[NameObject("/FT")] = NameObject("/Sig")
    annot[NameObject("/T")] = ByteStringObject(field_name.encode("latin-1"))
    v_obj = DictionaryObject()
    v_obj[NameObject("/Type")] = NameObject("/Sig")
    v_obj[NameObject("/Filter")] = NameObject("/Adobe.PPKLite")
    v_obj[NameObject("/SubFilter")] = NameObject("/adbe.pkcs7.detached")
    v_obj[NameObject("/Reason")] = ByteStringObject(b"SNUC HACKS '26 Certificate")
    v_obj[NameObject("/Location")] = ByteStringObject(b"Shiv Nadar University, Chennai")
    v_obj[NameObject("/M")] = ByteStringObject(
        datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S").encode("latin-1")
    )
    annot[NameObject("/V")] = v_obj
    return annot

def sign_pdf_crypto(input_pdf: Path, output_pdf: Path, private_key,
                    certificate, other_certs, sig_box: tuple, hashalgo: str = "sha256"):
    x, y, w, h = sig_box

    reader = PdfReader(str(input_pdf))
    writer = PdfWriter()
    writer.incremental = True
    writer.append(reader)
    page = writer.pages[0]

    sig_annot = create_signature_annotation(x, y, w, h, "Sig1")
    if "/Annots" not in page:
        page[NameObject("/Annots")] = ArrayObject()
    page["/Annots"].append(sig_annot)

    if "/AcroForm" in writer.root_object:
        acroform = writer.root_object["/AcroForm"]
        if "/Fields" not in acroform:
            acroform[NameObject("/Fields")] = ArrayObject()
        acroform["/Fields"].append(sig_annot)

    output = io.BytesIO()
    writer.write(output)
    pdf_bytes = output.getvalue()

    md = hashlib.new(hashalgo)
    md.update(pdf_bytes)
    digest = md.digest()

    endesive_signer.sign(
        pdf_bytes, private_key, certificate, other_certs,
        hashalgo, attrs=True, signed_value=digest,
    )

    with open(output_pdf, "wb") as f:
        f.write(pdf_bytes)

def sign_pdf_full(input_pdf: Path, output_pdf: Path, stamp_img: Path,
                  sig_box: tuple, private_key, certificate, other_certs):
    x, y, w, h = sig_box

    stamped_pdf = io.BytesIO()
    doc = fitz.open(str(input_pdf))
    for page_num in range(len(doc)):
        page = doc[page_num]
        rect = fitz.Rect(x, y, x + w, y + h)
        page.insert_image(rect, filename=str(stamp_img), keep_proportion=False)
    doc.save(stamped_pdf, garbage=4, deflate=True, clean=True)
    doc.close()
    stamped_bytes = stamped_pdf.getvalue()

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(stamped_bytes)
        tmp_path = Path(tmp.name)

    try:
        sign_pdf_crypto(tmp_path, output_pdf, private_key, certificate,
                        other_certs, sig_box)
    finally:
        tmp_path.unlink(missing_ok=True)


def process_dir(input_dir: Path, output_dir: Path, stamp_img: Path,
               private_key, certificate, other_certs, sig_box):
    total = 0
    for pdf_path in sorted(input_dir.rglob("*.pdf")):
        rel = pdf_path.relative_to(input_dir)
        out_path = output_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)


        try:
            sign_pdf_full(pdf_path, out_path, stamp_img, sig_box,
                          private_key, certificate, other_certs)
            print(f"  OK   {rel}")
            total += 1
        except Exception as e:
            print(f"  FAIL {rel}: {e}")

    return total

def parse_args():
    parser = argparse.ArgumentParser(
        description="Sign SNUC Hacks certificates: stamp sign.png + cryptographic signature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sign.py --input-dir ./pdf --output-dir ./signed \\
                 --p12-file certificate.p12 --p12-password SECRET \\
                 --sign-file sign.png

  python sign.py -i ./pdf -o ./signed -p certificate.p12 -s secret -f sign.png

Environment override:
  --platform linux|darwin|windows  (auto-detected by default)
        """,
    )
    parser.add_argument("-i", "--input-dir", type=Path, required=True,
                        help="Directory containing PDF subfolders (participants/finalists/volunteers)")
    parser.add_argument("-o", "--output-dir", type=Path, required=True,
                        help="Output directory for signed PDFs")
    parser.add_argument("-p", "--p12-file", type=Path, required=True,
                        help="Path to P12/PKCS12 signing certificate")
    parser.add_argument("-s", "--p12-password", type=str, required=True,
                        help="Password for P12 certificate")
    parser.add_argument("-f", "--sign-file", type=Path, required=True,
                        help="Path to sign.png (stamp image)")
    parser.add_argument("--platform", choices=["linux", "darwin", "windows"],
                        default=None, help="Force platform (auto-detected by default)")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.platform:
        target_platform = args.platform
    else:
        plat_map = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}
        target_platform = plat_map.get(platform.system(), "linux")

    print(f"[{target_platform.upper()}] SNUC Hacks Certificate Signer")
    if not args.p12_file.exists():
        print(f"Error: P12 file not found: {args.p12_file}")
        sys.exit(1)
    if not args.sign_file.exists():
        print(f"Error: sign.png not found: {args.sign_file}")
        sys.exit(1)


    print(f"Loading certificate: {args.p12_file}")
    try:
        private_key, certificate, other_certs = load_p12(args.p12_file, args.p12_password)
        print(f"  Subject: {certificate.subject.rfc4514_string()}")
    except Exception as e:
        print(f"Error loading P12: {e}")
        sys.exit(1)

    img = Image.open(args.sign_file)
    print(f"Stamp image: {args.sign_file} ({img.size[0]}x{img.size[1]} px)")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    categories = ["participants", "finalists", "volunteers"]
    grand_total = 0

    for cat in categories:
        indir = args.input_dir / cat
        if not indir.exists():
            print(f"Skipping {cat}/ (not found)")
            continue

        print(f"\nProcessing {cat}/ ...")
        count = process_dir(
            indir, args.output_dir / cat, args.sign_file,
            private_key, certificate, other_certs, SIG_BOX
        )
        print(f"  → {count} signed")
        grand_total += count

    print(f"\n{'='*50}")
    print(f"Done. {grand_total} certificates → {args.output_dir}/")


if __name__ == "__main__":
    main()
