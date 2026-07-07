#!/usr/bin/env python3
"""Add Santhi Ma'am's signature (visible stamp + PKCS#7) to certificates
that already have Padmavathi Ma'am's stamp applied.

The cert PDFs in ``-i`` are expected to be the output of stage 1 — they
already contain Padmavathi Ma'am's signature stamp. This script layers
Santhi Ma'am's stamp on top and embeds her PKCS#7 detached signature.

Calibrated for the SNUC Hacks '26 certificate template (landscape A4,
842 x 595 pt). Adjust ``SIG_BOX`` below for a different template.

Requirements:
    pip install -r requirements.txt

Usage:
    python sign.py -i staged -o signed \
                   -f santhi.png -p certificate.p12 -s PASSWORD
"""

import argparse
import hashlib
import io
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 stdout on Windows so non-ASCII filenames print cleanly
# under cmd.exe's default cp1252 encoding.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import fitz  # PyMuPDF
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject,
        ByteStringObject,
        DictionaryObject,
        NameObject,
        NumberObject,
    )
    from endesive import signer as endesive_signer
    from cryptography.hazmat.primitives.serialization import pkcs12
    from PIL import Image
except ImportError as e:
    print(f"Error: missing dependency - {e}", file=sys.stderr)
    print("Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# SIG_BOX — Santhi's stamp position in PDF points (x, y, width, height).
# y=0 is BOTTOM of page in PDF coordinates.
#
# Calibrated for the SNUC Hacks '26 certificate template
# (snuchacks-participants-template.pdf, landscape A4 = 842 x 595 pt).
# Places the stamp in the empty space ABOVE the dash line above
# "DR. SANTHI NATARAJAN" on the LEFT side
# (dash at y=126.5, x=128..305 in PDF coords). Mirrors Faculty A's
# placement above DR. PADMAVATHI U on the right.
# ─────────────────────────────────────────────────────────────────────────────

SIG_BOX = (130, 132, 170, 50)

REASON = b"SNUC HACKS '26 Certificate"
LOCATION = b"Shiv Nadar University, Chennai"
DEFAULT_CATEGORIES = ("participants", "finalists", "volunteers")


# ─────────────────────────────────────────────────────────────────────────────
# P12 loading
# ─────────────────────────────────────────────────────────────────────────────

def load_p12(cert_path: Path, password: str):
    with open(cert_path, "rb") as f:
        p12_data = f.read()
    private_key, certificate, other_certs = pkcs12.load_key_and_certificates(
        p12_data, password.encode("utf-8")
    )
    return private_key, certificate, other_certs or []


# ─────────────────────────────────────────────────────────────────────────────
# Visual stamping — Santhi's PNG onto the PDF.
# SIG_BOX is in PDF-native (bottom-left) coordinates; fitz.Rect uses
# top-left, so we flip y here before passing the rect in.
# ─────────────────────────────────────────────────────────────────────────────

def stamp_pdf_to_bytes(input_pdf: Path, stamp_img: Path, sig_box: tuple) -> bytes:
    x, y, w, h = sig_box
    buf = io.BytesIO()
    doc = fitz.open(str(input_pdf))
    page_h = doc[0].rect.height
    rect = fitz.Rect(x, page_h - y - h, x + w, page_h - y)
    for page in doc:
        page.insert_image(rect, filename=str(stamp_img), keep_proportion=False)
    doc.save(buf, garbage=4, deflate=True, clean=True)
    doc.close()
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Cryptographic signing — manual CMS signing because endesive 2.x's
# in-place signing was removed and the high-level endesive.pdf.cms.sign
# misparses our PDFs. We reserve a fixed-width /ByteRange placeholder,
# inject a /Contents placeholder, hash the bytes outside the
# placeholder, sign with endesive, then substitute the CMS blob.
# ─────────────────────────────────────────────────────────────────────────────

def create_signature_annotation(x, y, w, h, field_name, reason, location):
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
    v_obj[NameObject("/Reason")] = ByteStringObject(reason)
    v_obj[NameObject("/Location")] = ByteStringObject(location)
    v_obj[NameObject("/M")] = ByteStringObject(
        datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S").encode("latin-1")
    )
    annot[NameObject("/V")] = v_obj
    return annot


def sign_pdf_crypto(input_pdf, output_pdf, private_key, certificate,
                    other_certs, sig_box, hashalgo="sha256",
                    field_name="Sig1", reason=REASON, location=LOCATION):
    x, y, w, h = sig_box

    contents_reserve = 16384  # hex chars reserved for /Contents placeholder
    placeholder_hex = b"0" * contents_reserve
    placeholder = b"<" + placeholder_hex + b">"
    byterange_width = 50  # fixed inner width for /ByteRange
    byterange_placeholder = b"[" + b" " * byterange_width + b"]"

    reader = PdfReader(str(input_pdf))
    writer = PdfWriter(reader, incremental=True)
    page = writer.pages[0]

    sig_annot = create_signature_annotation(
        x, y, w, h, field_name=field_name, reason=reason, location=location
    )
    v_obj = sig_annot["/V"]
    v_obj[NameObject("/Contents")] = ByteStringObject(placeholder)
    v_obj[NameObject("/ByteRange")] = ByteStringObject(byterange_placeholder)

    if "/Annots" not in page:
        page[NameObject("/Annots")] = ArrayObject()
    page["/Annots"].append(sig_annot)
    if "/AcroForm" in writer.root_object:
        acroform = writer.root_object["/AcroForm"]
        if "/Fields" not in acroform:
            acroform[NameObject("/Fields")] = ArrayObject()
        acroform["/Fields"].append(sig_annot)

    out = io.BytesIO()
    writer.write(out)
    pdf_bytes = out.getvalue()

    # Locate the placeholder's '<' and '>'. pypdf HEX-encodes the
    # /Contents bytes, so the literal "<000...>" never appears — find
    # the /Contents < instead.
    contents_idx = pdf_bytes.rfind(b"/Contents <")
    if contents_idx < 0:
        raise RuntimeError("Could not find /Contents <...> after pypdf write")
    lt_idx = contents_idx + len(b"/Contents ")
    gt_idx = pdf_bytes.find(b">", lt_idx + 1)
    if gt_idx < 0:
        raise RuntimeError("Could not find closing > for /Contents placeholder")

    len1 = lt_idx
    start2 = gt_idx + 1
    len2 = len(pdf_bytes) - start2
    inner = f"0 {len1} {start2} {len2}".encode("ascii")
    if len(inner) > byterange_width:
        raise RuntimeError(
            f"ByteRange ({len(inner)} chars) exceeds reserved width "
            f"({byterange_width})."
        )
    inner = inner + b" " * (byterange_width - len(inner))
    new_br_value = b"[" + inner + b"]"
    br_idx = pdf_bytes.find(b"/ByteRange")
    br_bracket_start = pdf_bytes.find(b"[", br_idx)
    br_bracket_end = br_bracket_start + 1 + byterange_width
    pdf_bytes = (
        pdf_bytes[:br_bracket_start]
        + new_br_value
        + pdf_bytes[br_bracket_end + 1:]
    )

    # Digest the bytes excluding the <...> brackets themselves —
    # the verifier recomputes the hash over this same range.
    digest_data = pdf_bytes[:lt_idx] + pdf_bytes[gt_idx + 1:]
    md = hashlib.new(hashalgo)
    md.update(digest_data)
    digest = md.digest()

    cms_blob = endesive_signer.sign(
        digest_data, private_key, certificate, other_certs,
        hashalgo, attrs=True, signed_value=digest,
    )
    if not isinstance(cms_blob, (bytes, bytearray)) or len(cms_blob) == 0:
        raise RuntimeError(f"endesive returned unexpected value: {type(cms_blob)}")
    cms_hex = cms_blob.hex().encode("ascii")
    contents_inner_len = gt_idx - lt_idx - 1
    if len(cms_hex) > contents_inner_len:
        raise RuntimeError(
            f"Signature too large ({len(cms_hex)} hex chars) for "
            f"reserved contents size ({contents_inner_len})."
        )
    cms_hex = cms_hex + b"0" * (contents_inner_len - len(cms_hex))
    pdf_bytes = pdf_bytes[: lt_idx + 1] + cms_hex + pdf_bytes[gt_idx:]

    Path(output_pdf).write_bytes(pdf_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Temp file helper — mkstemp + close, so Windows file locks don't
# interfere with pypdf reopening the path.
# ─────────────────────────────────────────────────────────────────────────────

def write_to_temp_pdf(data: bytes) -> Path:
    fd, name = tempfile.mkstemp(suffix=".pdf")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


# ─────────────────────────────────────────────────────────────────────────────
# Per-PDF + per-directory processing
# ─────────────────────────────────────────────────────────────────────────────

def process_pdf(input_pdf, output_pdf, stamp_img, sig_box, pkey, cert, chain,
                field_name, reason, location):
    stamped = stamp_pdf_to_bytes(input_pdf, stamp_img, sig_box)
    tmp = write_to_temp_pdf(stamped)
    try:
        sign_pdf_crypto(
            tmp, output_pdf, pkey, cert, chain, sig_box,
            field_name=field_name, reason=reason, location=location,
        )
    finally:
        tmp.unlink(missing_ok=True)


def process_dir(input_dir, output_dir, stamp_img, pkey, cert, chain,
                sig_box, field_name, reason, location) -> int:
    total = 0
    for pdf_path in sorted(input_dir.rglob("*.pdf")):
        rel = pdf_path.relative_to(input_dir)
        out_path = output_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            process_pdf(
                pdf_path, out_path, stamp_img, sig_box,
                pkey, cert, chain,
                field_name=field_name, reason=reason, location=location,
            )
            print(f"  OK   {rel}")
            total += 1
        except Exception as e:
            print(f"  FAIL {rel}: {e}")

    return total


def parse_args():
    parser = argparse.ArgumentParser(
        description="Add Santhi Ma'am's signature (stamp + PKCS#7) to "
                    "Padmavathi-stamped cert PDFs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python sign.py -i staged -o signed \\
                 -f santhi.png -p certificate.p12 -s YOUR_PASSWORD
        """,
    )
    parser.add_argument("-i", "--input-dir", type=Path, required=True,
                        help="Folder with participants/, finalists/, volunteers/ "
                             "PDFs (already stamped by stage 1)")
    parser.add_argument("-o", "--output-dir", type=Path, required=True,
                        help="Output folder for signed PDFs")
    parser.add_argument("-f", "--sign-file", type=Path, required=True,
                        help="Santhi's signature PNG or JPG")
    parser.add_argument("-p", "--p12-file", type=Path, required=True,
                        help="Santhi's .p12 / PKCS#12 signing certificate")
    parser.add_argument("-s", "--p12-password", required=True,
                        help="Password for the P12")
    parser.add_argument("--field-name", default="Sig1",
                        help="Signature field name (default: Sig1)")
    parser.add_argument("--reason", default=None,
                        help="Override /Reason string (latin-1 encodable)")
    parser.add_argument("--location", default=None,
                        help="Override /Location string (latin-1 encodable)")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.p12_file.exists():
        print(f"Error: P12 file not found: {args.p12_file}")
        sys.exit(1)
    if not args.sign_file.exists():
        print(f"Error: sign image not found: {args.sign_file}")
        sys.exit(1)

    with Image.open(args.sign_file) as img:
        print(f"Stamp image: {args.sign_file} ({img.size[0]}x{img.size[1]} px)")

    print(f"Loading certificate: {args.p12_file}")
    try:
        private_key, certificate, other_certs = load_p12(args.p12_file, args.p12_password)
        print(f"  Subject: {certificate.subject.rfc4514_string()}")
    except Exception as e:
        print(f"Error loading P12: {e}")
        sys.exit(1)

    reason = args.reason.encode("latin-1") if args.reason else REASON
    location = args.location.encode("latin-1") if args.location else LOCATION

    args.output_dir.mkdir(parents=True, exist_ok=True)

    grand_total = 0
    for cat in DEFAULT_CATEGORIES:
        indir = args.input_dir / cat
        if not indir.exists():
            print(f"\nSkipping {cat}/ (not found)")
            continue
        print(f"\nProcessing {cat}/ ...")
        count = process_dir(
            indir, args.output_dir / cat, args.sign_file,
            private_key, certificate, other_certs, SIG_BOX,
            field_name=args.field_name, reason=reason, location=location,
        )
        print(f"  -> {count} signed")
        grand_total += count

    print(f"\n{'='*50}")
    print(f"Done. {grand_total} certificates -> {args.output_dir}/")


if __name__ == "__main__":
    main()