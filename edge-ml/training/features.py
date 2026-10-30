"""Python mirror of edge-ml/crates/edge-ml/src/features.rs (PE subset).

FEATURE_NAMES order is a contract with every exported model. tests/test_parity.py
checks this file against the Rust extractor (`edgeml features`).
"""

from __future__ import annotations

import math
from collections import Counter

import pefile

FEATURE_NAMES = [
    "size_log2", "entropy", "is_pe", "is_elf", "is_64bit", "is_dll", "num_sections", "max_section_entropy",
    "num_wx_sections", "num_imports", "num_import_dlls", "suspicious_imports", "has_signature", "has_debug",
    "has_tls", "overlay_ratio", "packer_section", "entry_outside_code", "timestamp_anomaly", "num_exports", "url_count",
]
SUSPICIOUS_IMPORTS = {
    "virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "zwunmapviewofsection",
    "setwindowshookexa", "setwindowshookexw", "queueuserapc", "ntqueueapcthread", "readprocessmemory",
    "minidumpwritedump", "cryptencrypt", "bcryptencrypt", "adjusttokenprivileges", "urldownloadtofilea",
    "urldownloadtofilew", "winexec", "isdebuggerpresent", "setthreadcontext", "resumethread",
}
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".packed", ".themida", ".vmp0", ".vmp1", "mpress1"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def url_count(data: bytes) -> float:
    n = sum(1 for i in range(len(data) - 6) if data[i:i + 7] in (b"http://", b"https:/"))
    return float(min(n, 50))


def extract(data: bytes) -> dict[str, float] | None:
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return None
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f["size_log2"] = math.log2(max(len(data), 1))
    f["entropy"] = entropy(data)
    f["url_count"] = url_count(data)
    f["is_pe"] = 1.0
    f["is_64bit"] = float(pe.OPTIONAL_HEADER.Magic == 0x20B)
    f["is_dll"] = float(bool(pe.FILE_HEADER.Characteristics & 0x2000))
    secs = pe.sections
    f["num_sections"] = float(len(secs))
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    raw_end, entry_ok = 0, False
    for i, s in enumerate(secs):
        body = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        f["max_section_entropy"] = max(f["max_section_entropy"], entropy(body))
        c = s.Characteristics
        if c & 0x20000000 and c & 0x80000000:
            f["num_wx_sections"] += 1
        if s.Name.rstrip(b"\0").decode("latin-1").lower() in PACKER_SECTIONS:
            f["packer_section"] = 1.0
        raw_end = max(raw_end, s.PointerToRawData + s.SizeOfRawData)
        vsize = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= entry < s.VirtualAddress + vsize:
            entry_ok = bool(c & 0x20) and (i + 1 < len(secs) or len(secs) == 1)
    f["entry_outside_code"] = 0.0 if entry_ok else 1.0
    f["overlay_ratio"] = max(0, len(data) - raw_end) / max(len(data), 1)
    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    names = [(imp.name or b"").decode("latin-1").lower() for e in imports for imp in e.imports]
    f["num_imports"] = float(len(names))
    f["num_import_dlls"] = float(len({e.dll.lower() for e in imports}))
    f["suspicious_imports"] = float(sum(n in SUSPICIOUS_IMPORTS for n in names))
    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    f["num_exports"] = float(len(exports.symbols)) if exports else 0.0
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    f["has_signature"] = float(sec_dir.Size > 0)
    f["has_debug"] = float(bool(getattr(pe, "DIRECTORY_ENTRY_DEBUG", None)))
    f["has_tls"] = float(bool(getattr(pe, "DIRECTORY_ENTRY_TLS", None)))
    ts = pe.FILE_HEADER.TimeDateStamp
    f["timestamp_anomaly"] = float(ts == 0 or ts > 1_900_000_000)
    return f
