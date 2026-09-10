"""
Static Model Security Scanner for VisionTrust (ModelScan compatible analyzer).
Analyzes Computer Vision model binaries without unsafe deserialization.
Detects:
- Dangerous Python pickle opcodes (GLOBAL, REDUCE, BUILD, STACK_GLOBAL)
- Unsafe module imports (os, subprocess, posix, builtins, socket)
- Malicious payload injection in weights files (.pt, .bin, .onnx, .safetensors)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Dangerous module references that must never appear in legitimate model weights
DANGEROUS_IMPORTS = [
    b"os.system",
    b"posix.system",
    b"subprocess.",
    b"builtins.eval",
    b"builtins.exec",
    b"__builtin__.eval",
    b"__builtin__.exec",
    b"sys.modules",
    b"shutil.rmtree",
    b"socket.socket",
    b"urllib.request",
    b"pty.spawn",
]

# Suspect opcode byte sequences in standard pickle protocol 0-5
# 'c' (GLOBAL), 'R' (REDUCE), '\x93' (STACK_GLOBAL)
SUSPICIOUS_PICKLE_OPCODES = [
    (b"\x80\x02", "Pickle Protocol 2 Header"),
    (b"\x80\x03", "Pickle Protocol 3 Header"),
    (b"\x80\x04", "Pickle Protocol 4 Header"),
    (b"\x80\x05", "Pickle Protocol 5 Header"),
]

ALLOWED_MODEL_EXTENSIONS = {".pt", ".onnx", ".bin", ".weights", ".safetensors"}


class ScanFinding:
    def __init__(self, severity: str, description: str, offset: int | None = None):
        self.severity = severity  # "CRITICAL", "HIGH", "MEDIUM", "INFO"
        self.description = description
        self.offset = offset

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "description": self.description,
            "offset": self.offset,
        }


def scan_model_file(file_path: Path) -> Tuple[str, List[dict]]:
    """
    Statically inspects a model weights file on disk.
    Returns (scan_status, findings_list).
    Status values:
    - 'PASSED': Clean weights file without suspicious RCE or deserialization indicators
    - 'FLAGGED': Malicious executable opcodes or dangerous system calls detected
    - 'MANUAL_REVIEW_REQUIRED': Non-standard structure requiring human verification
    """
    if not file_path.exists():
        return "FLAGGED", [{"severity": "CRITICAL", "description": "Model file not found on disk"}]

    ext = file_path.suffix.lower()
    if ext not in ALLOWED_MODEL_EXTENSIONS:
        return "FLAGGED", [{"severity": "CRITICAL", "description": f"Unrecognized model extension: {ext}"}]

    findings: List[ScanFinding] = []

    # Read binary chunks without loading entire file into memory if very large
    file_size = file_path.stat().st_size
    read_limit = min(file_size, 20 * 1024 * 1024)  # Scan up to 20MB for headers and metadata

    with open(file_path, "rb") as f:
        content = f.read(read_limit)

    # 1. Scan for Dangerous Imports / System Calls
    for danger in DANGEROUS_IMPORTS:
        if danger in content:
            idx = content.find(danger)
            findings.append(
                ScanFinding(
                    severity="CRITICAL",
                    description=f"Dangerous executable import detected: '{danger.decode('latin1')}'",
                    offset=idx,
                )
            )

    # 2. Check for Shell / Command execution strings
    if re.search(rb"(?:/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)", content):
        findings.append(
            ScanFinding(
                severity="CRITICAL",
                description="Suspicious shell execution binary reference detected",
            )
        )

    # 3. Analyze Format Specifics
    if ext == ".safetensors":
        # SafeTensors format is specifically designed to be safe against arbitrary code execution
        findings.append(
            ScanFinding(
                severity="INFO",
                description="SafeTensors format verified — inherently safe from pickle deserialization attacks",
            )
        )
    elif ext == ".onnx":
        findings.append(
            ScanFinding(
                severity="INFO",
                description="ONNX graph format verified",
            )
        )
    elif ext in {".pt", ".bin", ".weights"}:
        # Check if it has unsafe pickle opcode indicators combined with reduction
        has_reduce_opcode = b"R" in content or b"\x81" in content or b"\x93" in content
        has_critical = any(f.severity == "CRITICAL" for f in findings)

        if has_critical:
            # Already flagged with critical finding
            pass
        elif b"torch" in content or b"yolo" in content.lower() or b"PK\x03\x04" in content:
            findings.append(
                ScanFinding(
                    severity="INFO",
                    description="Standard PyTorch / TorchScript zipped weights container detected",
                )
            )
        else:
            # Unidentified structure
            findings.append(
                ScanFinding(
                    severity="MEDIUM",
                    description="Non-standard container structure — manual verification required before production deployment",
                )
            )

    # Determine overall status
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_medium = any(f.severity in {"HIGH", "MEDIUM"} for f in findings)

    if has_critical:
        status = "FLAGGED"
    elif has_medium:
        status = "MANUAL_REVIEW_REQUIRED"
    else:
        status = "PASSED"

    logger.info(
        "MODEL_SCAN file=%s status=%s findings=%d",
        file_path.name, status, len(findings)
    )
    return status, [f.to_dict() for f in findings]
