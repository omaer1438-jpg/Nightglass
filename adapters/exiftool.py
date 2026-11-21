"""14 ImageMeta: ExifTool JSON parser (exiftool -json -n -G1 -a -- <file>). Local only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.findings import Confidence, Finding, ResultKind
from core.modules import ModuleSpec, ParseResult
from core.validation import TargetType

MODULE_NAME = "ImageMeta"

_FIELDS = [
    # (title, keys tried in order)
    ("File type", ["File:FileType"]),
    ("Image size", ["Composite:ImageSize"]),
    ("Camera make", ["IFD0:Make"]),
    ("Camera model", ["IFD0:Model"]),
    ("Software", ["IFD0:Software", "XMP-xmp:CreatorTool"]),
    ("Artist / creator", ["IFD0:Artist", "XMP-dc:Creator"]),
    ("Copyright", ["IFD0:Copyright", "XMP-dc:Rights"]),
    ("Taken (original time)", ["ExifIFD:DateTimeOriginal"]),
    ("Created (digitized time)", ["ExifIFD:CreateDate"]),
    ("Modified (metadata time)", ["IFD0:ModifyDate"]),
    ("Comment", ["File:Comment", "ExifIFD:UserComment"]),
]


def console_tag(line: str) -> str:
    return "c" if "GPS" in line else ""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dhash(path: Path) -> str | None:
    """64-bit difference hash: grayscale, 9x8, each pixel compared with its right neighbour. None if unreadable.
    Resized or re-encoded copies of an image get the same or a near hash (a few bits apart)."""
    from PySide6.QtCore import QSize, Qt
    from PySide6.QtGui import QImage, QImageReader, qGray

    reader = QImageReader(str(path))
    reader.setAutoTransform(True)
    size = reader.size()
    if size.width() > 512 and size.height() > 512:  # decode big photos small: the hash only needs 9x8
        reader.setScaledSize(size.scaled(QSize(512, 512), Qt.AspectRatioMode.KeepAspectRatio))
    image = reader.read()
    if image.isNull():
        return None
    small = image.convertToFormat(QImage.Format.Format_Grayscale8).scaled(
        9, 8, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
    bits = 0
    for y in range(8):
        for x in range(8):
            bits = bits << 1 | (qGray(small.pixel(x + 1, y)) > qGray(small.pixel(x, y)))
    return f"{bits:016x}"


def parse(lines: list[str], work_dir: Path | None = None, target: str = "") -> ParseResult:
    text = "\n".join(lines)
    start = text.find("[")
    if start < 0:
        raise ValueError(text.strip()[:200] or "ExifTool returned no data.")
    records = json.loads(text[start:])
    if not records:
        raise ValueError("ExifTool returned no data.")
    record = records[0]
    if "Error" in record or "ExifTool:Error" in record:
        raise ValueError(str(record.get("Error") or record.get("ExifTool:Error")))

    def finding(title: str, value, confidence=Confidence.HIGH, result=ResultKind.INFO, notes="") -> Finding:
        return Finding(module=MODULE_NAME, title=title, value=str(value)[:4000], source="ExifTool",
                       confidence=confidence, result=result, raw_ref="run.log", notes=notes)

    findings = []
    if target and Path(target).is_file():
        findings.append(finding("SHA-256", sha256_of(Path(target)), notes=f"File: {Path(target).name}"))
        visual = dhash(Path(target))
        if visual:
            findings.append(finding("Perceptual hash (dHash)", f"dhash:{visual}",
                                    notes="Same for resized or re-saved copies of this picture. A match means "
                                          "the images look alike, not that they are the same file."))
    for title, keys in _FIELDS:
        for key in keys:
            if record.get(key) not in (None, ""):
                findings.append(finding(title, record[key]))
                break
    lat, lon = record.get("Composite:GPSLatitude"), record.get("Composite:GPSLongitude")
    if lat is not None and lon is not None:
        findings.append(finding(
            "GPS location in metadata", f"{lat}, {lon}", result=ResultKind.FOUND,
            notes="Coordinates stored in the file. They may be wrong, edited or not where the image was taken.",
        ))
    else:
        findings.append(finding("No GPS data", "The file has no GPS coordinates (never set, or stripped)."))
    return ParseResult(findings, {"fields": len(record), "gps": int(lat is not None and lon is not None)})


MODULE = ModuleSpec(
    number="14",
    id="imagemeta",
    name=MODULE_NAME,
    icon="img",
    description="EXIF, GPS, camera and timestamps from a local file, plus its SHA-256 and perceptual hash.",
    labels=("local",),
    target_types=(TargetType.FILE,),
    provider="Nothing leaves this computer (ExifTool runs locally)",
    tools=("exiftool",),
    console_tag=console_tag,
    timeout_s=60,
    max_output_kb=2048,
)
