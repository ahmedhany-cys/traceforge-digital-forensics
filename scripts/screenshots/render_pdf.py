"""Render pages of a generated TraceForge PDF report side by side into one PNG.

    python render_pdf.py ../../docs/sample-reports/RPT-....pdf ../../screenshots/13-pdf-report.png

Pages rendered: the cover, the page containing the reconstructed sequences
section, and the first malware-analysis page. Requires pypdfium2 (Pillow comes with it).
"""

from __future__ import annotations

import sys

import pypdfium2 as pdfium
from PIL import Image

WANTED = ["Digital Forensic Investigation Report", "Reconstructed sequences", "Malware static analysis"]


def main(src: str, dest: str) -> None:
    pdf = pdfium.PdfDocument(src)
    texts = [pdf[i].get_textpage().get_text_range() for i in range(len(pdf))]
    pages = []
    for marker in WANTED:
        idx = next(i for i, t in enumerate(texts) if marker in t and i not in pages)
        pages.append(idx)
    images = [pdf[i].render(scale=1.6).to_pil() for i in pages]
    gap = 24
    width = sum(im.width for im in images) + gap * (len(images) + 1)
    height = max(im.height for im in images) + 2 * gap
    canvas = Image.new("RGB", (width, height), (15, 23, 42))
    x = gap
    for im in images:
        canvas.paste(im, (x, gap))
        x += im.width + gap
    canvas.save(dest, optimize=True)
    print(f"rendered pages {[p + 1 for p in pages]} of {len(pdf)} -> {dest}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
