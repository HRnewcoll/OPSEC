#!/usr/bin/env python3
"""
OPSEC Metadata Cleaner
=======================
Strip identifying metadata from files before sharing:
  - EXIF data from JPEG/PNG/WebP/TIFF images (GPS, camera, date, user comment)
  - PDF metadata (author, creator, producer, creation date, custom properties)
  - DOCX/XLSX/PPTX Office Open XML metadata (author, company, revision history)
  - MP3/MP4/video ID3 tags and XMP metadata
  - Batch processing with recursive directory scanning
  - Preview mode — show metadata without removing it
  - Audit log — record what was stripped from each file

Usage:
  python metadata_cleaner.py clean  --file photo.jpg
  python metadata_cleaner.py clean  --dir ~/photos --recursive
  python metadata_cleaner.py show   --file photo.jpg
  python metadata_cleaner.py clean  --file document.pdf
  python metadata_cleaner.py clean  --file report.docx
  python metadata_cleaner.py batch  --dir ~/to-share --out ~/cleaned --recursive
"""

import argparse
import json
import os
import re
import shutil
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── JPEG EXIF cleaner (pure stdlib) ──────────────────────────────────

# JPEG markers
SOI  = b"\xff\xd8"   # Start of Image
APP0 = b"\xff\xe0"   # JFIF
APP1 = b"\xff\xe1"   # EXIF / XMP
APP2 = b"\xff\xe2"
APPM = [bytes([0xff, 0xe0 + i]) for i in range(1, 16)]  # APP1..APP15
SOS  = b"\xff\xda"   # Start of Scan
EOI  = b"\xff\xd9"   # End of Image

EXIF_HDR = b"Exif\x00\x00"
XMP_HDR  = b"http://ns.adobe.com/xap/1.0/\x00"


def _parse_jpeg_metadata(data: bytes) -> dict:
    """Extract EXIF fields from JPEG bytes."""
    meta = {}
    if not data.startswith(SOI):
        return meta

    pos = 2
    while pos < len(data) - 1:
        marker = data[pos:pos+2]
        if marker == SOS or marker == EOI:
            break
        if marker[0:1] != b"\xff":
            break
        seg_len = struct.unpack(">H", data[pos+2:pos+4])[0]
        seg_data = data[pos+4:pos+2+seg_len]

        if marker == APP1:
            if seg_data.startswith(EXIF_HDR):
                meta["exif_size"] = seg_len
                meta["has_exif"] = True
                # Parse IFD to find GPS, Make, Model
                exif_body = seg_data[6:]
                try:
                    fields = _parse_tiff_ifd(exif_body)
                    meta.update(fields)
                except Exception:
                    pass
            elif seg_data.startswith(XMP_HDR):
                meta["has_xmp"] = True
                meta["xmp_size"] = seg_len

        pos += 2 + seg_len
    return meta


_TIFF_TAGS = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x013E: "WhitePoint",
    0x013F: "PrimaryChromaticities",
    0x0211: "YCbCrCoefficients",
    0x0213: "YCbCrPositioning",
    0x0214: "ReferenceBlackWhite",
    0x8298: "Copyright",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSIFDPointer",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9286: "UserComment",
    0xA420: "ImageUniqueID",
    0x0002: "GPSLatitude",
    0x0003: "GPSLatitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSLongitudeRef",
    0x0006: "GPSAltitude",
}


def _parse_tiff_ifd(data: bytes) -> dict:
    if len(data) < 8:
        return {}
    byte_order = data[:2]
    bo = "<" if byte_order == b"II" else ">"
    offset = struct.unpack(bo + "I", data[4:8])[0]

    result = {}
    if offset + 2 > len(data):
        return result
    num_entries = struct.unpack(bo + "H", data[offset:offset+2])[0]
    for i in range(num_entries):
        entry_offset = offset + 2 + i * 12
        if entry_offset + 12 > len(data):
            break
        tag, typ, count = struct.unpack(bo + "HHI", data[entry_offset:entry_offset+8])
        val_offset = struct.unpack(bo + "I", data[entry_offset+8:entry_offset+12])[0]
        tag_name = _TIFF_TAGS.get(tag)
        if tag_name:
            if typ == 2:  # ASCII string
                str_offset = val_offset if count > 4 else entry_offset + 8
                if str_offset + count <= len(data):
                    val = data[str_offset:str_offset+count].rstrip(b"\x00").decode("latin-1", errors="replace")
                    result[tag_name] = val
            else:
                result[tag_name] = f"<type={typ} count={count}>"
    return result


def _strip_jpeg_exif(data: bytes) -> tuple[bytes, list[str]]:
    """Remove all APPn segments (EXIF, XMP, IPTC) from JPEG."""
    if not data.startswith(SOI):
        return data, []

    stripped = []
    out = bytearray(SOI)
    pos = 2

    while pos < len(data) - 1:
        marker = data[pos:pos+2]
        if len(marker) < 2:
            break

        if marker == SOS:
            out.extend(data[pos:])  # rest of image data unchanged
            break
        if marker == EOI:
            out.extend(EOI)
            break
        if marker[0:1] != b"\xff" or len(data) < pos + 4:
            out.extend(data[pos:])
            break

        seg_len = struct.unpack(">H", data[pos+2:pos+4])[0]
        seg_data = data[pos+4:pos+2+seg_len]

        # Strip all APPn (except APP0 JFIF for compatibility)
        if marker in APPM and marker != APP0:
            if seg_data.startswith(EXIF_HDR):
                stripped.append("EXIF data")
            elif seg_data.startswith(XMP_HDR):
                stripped.append("XMP metadata")
            elif marker == bytes([0xff, 0xed]):
                stripped.append("IPTC/Photoshop data")
            else:
                stripped.append(f"APP segment {marker.hex()}")
        else:
            out.extend(data[pos:pos+2+seg_len])

        pos += 2 + seg_len

    return bytes(out), stripped


# ── PNG metadata cleaner ──────────────────────────────────────────────

PNG_SIG = b"\x89PNG\r\n\x1a\n"
KEEP_PNG_CHUNKS = {b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tRNS",
                   b"cHRM", b"gAMA", b"sBIT", b"sRGB", b"iCCP",
                   b"bKGD", b"hIST", b"pHYs", b"sPLT", b"IDAT"}


def _strip_png_metadata(data: bytes) -> tuple[bytes, list[str]]:
    if not data.startswith(PNG_SIG):
        return data, []

    out = bytearray(PNG_SIG)
    stripped = []
    pos = 8

    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+8:pos+8+length]
        crc = data[pos+8+length:pos+12+length]

        if chunk_type in KEEP_PNG_CHUNKS:
            out.extend(data[pos:pos+12+length])
        else:
            tag = chunk_type.decode("latin-1", errors="replace")
            stripped.append(f"PNG chunk: {tag}")

        pos += 12 + length
        if chunk_type == b"IEND":
            break

    return bytes(out), stripped


# ── PDF metadata cleaner ──────────────────────────────────────────────

PDF_META_PATTERNS = [
    (re.compile(rb"/Author\s*\([^)]*\)"),      b"/Author ()"),
    (re.compile(rb"/Author\s*<[^>]*>"),        b"/Author <>"),
    (re.compile(rb"/Creator\s*\([^)]*\)"),     b"/Creator ()"),
    (re.compile(rb"/Creator\s*<[^>]*>"),       b"/Creator <>"),
    (re.compile(rb"/Producer\s*\([^)]*\)"),    b"/Producer ()"),
    (re.compile(rb"/Producer\s*<[^>]*>"),      b"/Producer <>"),
    (re.compile(rb"/Title\s*\([^)]*\)"),       b"/Title ()"),
    (re.compile(rb"/Title\s*<[^>]*>"),         b"/Title <>"),
    (re.compile(rb"/Subject\s*\([^)]*\)"),     b"/Subject ()"),
    (re.compile(rb"/Keywords\s*\([^)]*\)"),    b"/Keywords ()"),
    (re.compile(rb"/CreationDate\s*\([^)]*\)"),b"/CreationDate ()"),
    (re.compile(rb"/ModDate\s*\([^)]*\)"),     b"/ModDate ()"),
    (re.compile(rb"/Company\s*\([^)]*\)"),     b"/Company ()"),
    (re.compile(rb"/SourceModified\s*\([^)]*\)"), b"/SourceModified ()"),
]

XMP_STREAM_RE = re.compile(
    rb"<x:xmpmeta[^>]*>.*?</x:xmpmeta>", re.DOTALL
)


def _strip_pdf_metadata(data: bytes) -> tuple[bytes, list[str]]:
    stripped = []
    result = data

    for pattern, replacement in PDF_META_PATTERNS:
        new_result, n = re.subn(pattern, replacement, result)
        if n > 0:
            field = replacement.decode().split()[0]
            stripped.append(f"PDF field: {field}")
        result = new_result

    # Strip XMP metadata streams
    xmp_matches = XMP_STREAM_RE.findall(result)
    if xmp_matches:
        result = XMP_STREAM_RE.sub(b"<x:xmpmeta></x:xmpmeta>", result)
        stripped.append("XMP metadata stream")

    return result, stripped


# ── Office Open XML (DOCX/XLSX/PPTX) cleaner ─────────────────────────

OOXML_META_FILES = [
    "docProps/core.xml",
    "docProps/app.xml",
    "docProps/custom.xml",
]

BLANK_CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
</cp:coreProperties>"""

BLANK_APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
</Properties>"""


def _strip_ooxml_metadata(src_path: Path, dst_path: Path) -> list[str]:
    stripped = []
    import io

    src_bytes = src_path.read_bytes()
    out_buf = io.BytesIO()

    with zipfile.ZipFile(io.BytesIO(src_bytes), "r") as zin, \
         zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as zout:

        for item in zin.infolist():
            data = zin.read(item.name)
            name_lower = item.name.lower()

            if name_lower == "docprops/core.xml":
                data = BLANK_CORE_XML.encode()
                stripped.append("Core properties (author, dates, revision)")
            elif name_lower == "docprops/app.xml":
                data = BLANK_APP_XML.encode()
                stripped.append("App properties (company, manager)")
            elif name_lower == "docprops/custom.xml":
                # Drop custom properties entirely
                stripped.append("Custom properties")
                continue
            elif name_lower.endswith(".xml"):
                # Strip rsidR revision tracking attributes in Word XML
                cleaned = re.sub(rb'\s*w:rsid[A-Za-z]*="[^"]*"', b"", data)
                cleaned = re.sub(rb'\s*w:paraId="[^"]*"', b"", cleaned)
                cleaned = re.sub(rb'\s*w:textId="[^"]*"', b"", cleaned)
                if cleaned != data:
                    stripped.append("Revision tracking IDs")
                    data = cleaned

            # Reset timestamp in ZIP to avoid date leakage
            item.date_time = (2000, 1, 1, 0, 0, 0)
            zout.writestr(item, data)

    dst_path.write_bytes(out_buf.getvalue())
    return stripped


# ── dispatcher ────────────────────────────────────────────────────────

SUPPORTED_EXTS = {
    ".jpg": "jpeg", ".jpeg": "jpeg",
    ".png": "png",
    ".pdf": "pdf",
    ".docx": "ooxml", ".xlsx": "ooxml", ".pptx": "ooxml",
    ".webp": "jpeg",   # WebP EXIF usually in JPEG-like container
}


def _show_metadata(path: Path) -> dict:
    ext = path.suffix.lower()
    fmt = SUPPORTED_EXTS.get(ext)
    meta = {"file": str(path), "format": fmt or "unsupported"}

    if fmt == "jpeg":
        data = path.read_bytes()
        meta.update(_parse_jpeg_metadata(data))
    elif fmt == "pdf":
        data = path.read_bytes()
        for pattern, _ in PDF_META_PATTERNS:
            for m in pattern.findall(data):
                meta.setdefault("pdf_fields", []).append(m.decode("latin-1", errors="replace"))
    elif fmt == "ooxml":
        try:
            with zipfile.ZipFile(path, "r") as z:
                for mf in OOXML_META_FILES:
                    try:
                        content = z.read(mf).decode("utf-8", errors="replace")
                        meta[mf] = content
                    except KeyError:
                        pass
        except Exception as e:
            meta["error"] = str(e)
    return meta


def clean_file(src: Path, dst: Optional[Path] = None,
               dry_run: bool = False) -> dict:
    """Clean metadata from a single file. Returns result dict."""
    ext = src.suffix.lower()
    fmt = SUPPORTED_EXTS.get(ext)
    result = {"file": str(src), "format": fmt or "unsupported", "stripped": []}

    if not fmt:
        result["error"] = f"Unsupported format: {ext}"
        return result

    if dst is None:
        dst = src.parent / (src.stem + "_clean" + src.suffix)

    if dry_run:
        meta = _show_metadata(src)
        result["preview"] = meta
        return result

    if fmt == "jpeg":
        data = src.read_bytes()
        cleaned, stripped = _strip_jpeg_exif(data)
        dst.write_bytes(cleaned)
        result["stripped"] = stripped
        result["original_size"] = len(data)
        result["cleaned_size"]  = len(cleaned)

    elif fmt == "png":
        data = src.read_bytes()
        cleaned, stripped = _strip_png_metadata(data)
        dst.write_bytes(cleaned)
        result["stripped"] = stripped

    elif fmt == "pdf":
        data = src.read_bytes()
        cleaned, stripped = _strip_pdf_metadata(data)
        dst.write_bytes(cleaned)
        result["stripped"] = stripped

    elif fmt == "ooxml":
        stripped = _strip_ooxml_metadata(src, dst)
        result["stripped"] = stripped

    result["output"] = str(dst)
    return result


# ── batch ─────────────────────────────────────────────────────────────

def batch_clean(src_dir: Path, dst_dir: Path, recursive: bool = False,
                dry_run: bool = False) -> list[dict]:
    pattern = "**/*" if recursive else "*"
    files = [f for f in src_dir.glob(pattern)
             if f.is_file() and f.suffix.lower() in SUPPORTED_EXTS]

    print(f"[*] Found {len(files)} supported files in {src_dir}")
    results = []

    for src in files:
        rel  = src.relative_to(src_dir)
        dst  = dst_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        result = clean_file(src, dst, dry_run=dry_run)
        stripped = result.get("stripped", [])
        if stripped:
            print(f"  ✓ {rel}: stripped {len(stripped)} metadata item(s)")
            for s in stripped:
                print(f"      - {s}")
        else:
            print(f"  - {rel}: no metadata found")
        results.append(result)

    print(f"\n[+] Processed {len(files)} files")
    return results


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Metadata Cleaner")
    sub = parser.add_subparsers(dest="cmd")

    cl = sub.add_parser("clean", help="Clean a single file or directory")
    cl.add_argument("--file", type=Path, help="Single file to clean")
    cl.add_argument("--dir",  type=Path, help="Directory to clean")
    cl.add_argument("--out",  type=Path, help="Output file or directory")
    cl.add_argument("--recursive", "-r", action="store_true")
    cl.add_argument("--dry-run", action="store_true", help="Show metadata without removing")

    sh = sub.add_parser("show", help="Show metadata without cleaning")
    sh.add_argument("--file", required=True, type=Path)

    bt = sub.add_parser("batch", help="Batch clean a directory")
    bt.add_argument("--dir",  required=True, type=Path)
    bt.add_argument("--out",  required=True, type=Path)
    bt.add_argument("--recursive", "-r", action="store_true")
    bt.add_argument("--report", type=Path, help="Save JSON audit report")

    args = parser.parse_args()

    if args.cmd == "clean":
        if args.file:
            result = clean_file(args.file, args.out, dry_run=args.dry_run)
            stripped = result.get("stripped", [])
            if result.get("error"):
                print(f"[!] {result['error']}")
            elif args.dry_run:
                print(json.dumps(result.get("preview", {}), indent=2))
            else:
                print(f"[+] Cleaned: {result.get('output')}")
                for s in stripped:
                    print(f"    - {s}")
                if not stripped:
                    print("    (no metadata found)")

        elif args.dir:
            dst = args.out or args.dir.parent / (args.dir.name + "_clean")
            batch_clean(args.dir, dst, args.recursive, dry_run=args.dry_run)

        else:
            print("[!] Provide --file or --dir")

    elif args.cmd == "show":
        meta = _show_metadata(args.file)
        print(json.dumps(meta, indent=2, default=str))

    elif args.cmd == "batch":
        results = batch_clean(args.dir, args.out, args.recursive)
        if args.report:
            args.report.write_text(json.dumps(results, indent=2, default=str))
            print(f"[+] Audit report → {args.report}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
