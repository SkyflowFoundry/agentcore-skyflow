#!/usr/bin/env python3
"""Build the sample documents the demo uploads to S3.

Every value here is synthetic. The point is to have the same content in
three formats so the difference between a vault token and a counter is
visible rather than described.

Usage: python3 scripts/make_samples.py
"""
import pathlib
import zipfile

OUT = pathlib.Path(__file__).resolve().parents[1] / "samples"
OUT.mkdir(parents=True, exist_ok=True)

LINES = [
    "Claim note",
    "Customer: Daniel Okonkwo",
    "Email: daniel.okonkwo@example.com",
    "Phone: 555-0133",
    "Notes: follow up about the Chicago policy renewal.",
]


def build_pdf(path):
    """A minimal one page PDF with the lines drawn in Helvetica."""
    text_ops = ["BT", "/F1 12 Tf", "72 720 Td", "14 TL"]
    for line in LINES:
        text_ops.append(f"({line}) Tj")
        text_ops.append("T*")
    text_ops.append("ET")
    stream = "\n".join(text_ops).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    ).encode()
    path.write_bytes(bytes(out))


def build_docx(path):
    """A minimal Office Open XML document with one paragraph per line."""
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    paragraphs = "".join(
        f"<w:p><w:r><w:t xml:space='preserve'>{line}</w:t></w:r></w:p>" for line in LINES
    )
    document = f"<?xml version='1.0' encoding='UTF-8' standalone='yes'?><w:document {ns}><w:body>{paragraphs}</w:body></w:document>"

    content_types = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
        "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
        "<Default Extension='xml' ContentType='application/xml'/>"
        "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>"
        "</Types>"
    )
    rels = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>"
        "<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument' Target='word/document.xml'/>"
        "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)


build_pdf(OUT / "claim-note.pdf")
build_docx(OUT / "claim-note.docx")
for f in sorted(OUT.iterdir()):
    print(f"{f.name:20} {f.stat().st_size:6d} bytes")
