# 15 — Metadata Cleaner

Strip identifying metadata from files before sharing — images, PDFs, Office documents.

## Features
- **JPEG/WebP EXIF** — removes GPS, camera model, date/time, user comments, IPTC, XMP
- **PNG text chunks** — removes tEXt, iTXt, zTXt, tIME, and custom chunks
- **PDF metadata** — clears author, creator, producer, title, creation date, and XMP streams
- **DOCX/XLSX/PPTX** — blanks core.xml & app.xml, drops custom.xml, removes revision IDs
- **Dry-run / preview** — see what would be stripped without modifying files
- **Batch processing** — recursive directory cleaning
- **JSON audit report** — full log of what was stripped from each file
- **No external dependencies** — pure stdlib Python

## Supported Formats
| Extension | Format | Metadata removed |
|-----------|--------|-----------------|
| `.jpg` `.jpeg` `.webp` | JPEG | EXIF, XMP, IPTC, all APPn segments |
| `.png` | PNG | tEXt, iTXt, zTXt, tIME, eXIf, caNv |
| `.pdf` | PDF | Info dict fields, XMP streams |
| `.docx` `.xlsx` `.pptx` | OOXML | core.xml, app.xml, custom.xml, revision IDs |

## Usage

```bash
# Clean a single image
python metadata_cleaner.py clean --file photo.jpg
# → photo_clean.jpg

# Clean to specific output path
python metadata_cleaner.py clean --file photo.jpg --out /tmp/safe_photo.jpg

# Show metadata without removing (dry-run)
python metadata_cleaner.py show --file document.docx
python metadata_cleaner.py clean --file photo.jpg --dry-run

# Clean a PDF
python metadata_cleaner.py clean --file report.pdf --out report_clean.pdf

# Clean a Word document
python metadata_cleaner.py clean --file report.docx --out report_clean.docx

# Batch clean a folder
python metadata_cleaner.py batch --dir ~/to-share --out ~/cleaned

# Batch with recursive subfolder and audit report
python metadata_cleaner.py batch --dir ~/photos --out ~/cleaned_photos \
    --recursive --report audit.json

# Clean directory in-place (dry run first)
python metadata_cleaner.py clean --dir ~/to-share --dry-run
python metadata_cleaner.py clean --dir ~/to-share --out ~/to-share-clean
```

## Example Output

```
[*] Found 12 supported files in /home/user/photos
  ✓ vacation.jpg: stripped 3 metadata item(s)
      - EXIF data
      - XMP metadata
      - APP segment ffe2
  ✓ document.docx: stripped 2 metadata item(s)
      - Core properties (author, dates, revision)
      - App properties (company, manager)
  - screenshot.png: no metadata found

[+] Processed 12 files
```

## Privacy Notes
- EXIF GPS data in photos reveals **exact location** where photo was taken
- Camera model and serial numbers in EXIF can identify your device
- PDF Creator/Producer fields reveal what software (and version) you used
- DOCX revision history can expose previous drafts and author info
- Always clean before posting photos or documents publicly
