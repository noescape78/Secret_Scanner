"""
scanner.py - Secret Scanner Engine and Traversal Module

Handles filesystem scanning, binary detection, pattern evaluation,
secret masking, and CSV report exportation.
"""

import csv
import os
from typing import List, Dict, Any, Tuple, Optional, Callable

from patterns import SECRET_PATTERNS, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

# File extensions targeted for secret scanning
TARGET_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php",
    ".go", ".rb", ".json", ".yaml", ".yml", ".xml",
    ".env", ".conf", ".ini", ".cfg", ".toml", ".txt"
}

# Directories to ignore during scanning
IGNORED_DIRECTORIES = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "env", ".env.example", ".idea", ".vscode", "dist", "build",
    ".pytest_cache", ".mypy_cache"
}

# Maximum file size to scan (5 MB) to avoid performance lag
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def mask_secret(value: str) -> str:
    """
    Mask a sensitive value so it is never displayed or stored in plaintext.

    Examples:
        'sk_live_123456789abcdef' -> 'sk_l***************cdef'
        'FakePassword123'         -> 'Fa***********23'
        '12345'                   -> '*****'
    """
    cleaned = value.strip()
    length = len(cleaned)

    # Special handling for PEM header
    if "-----BEGIN" in cleaned:
        return "-----BEGIN [*** PRIVATE KEY ***]-----"

    if length <= 6:
        return "*" * length

    if length <= 10:
        # Keep 1 leading and 1 trailing char
        return cleaned[:1] + ("*" * (length - 2)) + cleaned[-1:]

    # For standard secrets, keep first 3 and last 3 characters, mask the rest
    leading = cleaned[:3]
    trailing = cleaned[-3:]
    masked_count = min(max(length - 6, 6), 16)
    return f"{leading}{'*' * masked_count}{trailing}"


def is_binary_file(filepath: str) -> bool:
    """
    Check if a file appears to be binary by looking for null bytes in the first 1024 bytes.
    """
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except OSError:
        return True


def should_scan_file(filepath: str) -> bool:
    """
    Determine whether a file should be scanned based on extension, size, and binary check.
    """
    filename = os.path.basename(filepath)

    # Allow files like .env or files with matching extensions
    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower()

    # Exact filename matches (like .env)
    if filename in [".env", ".env.local", ".env.development", ".env.production"]:
        pass
    elif ext_lower not in TARGET_EXTENSIONS:
        return False

    # Check size
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE_BYTES:
            return False
    except OSError:
        return False

    # Binary check
    if is_binary_file(filepath):
        return False

    return True


def scan_file(filepath: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Scan a single file line-by-line against all defined secret patterns.

    Returns:
        A tuple of (findings_list, error_message_if_any).
    """
    findings: List[Dict[str, Any]] = []

    # Attempt to open file safely with utf-8, fallback to latin-1
    encodings = ["utf-8", "latin-1"]
    content_lines = None
    last_error = None

    for enc in encodings:
        try:
            with open(filepath, "r", encoding=enc, errors="replace") as f:
                content_lines = f.readlines()
            break
        except (PermissionError, FileNotFoundError, OSError) as e:
            last_error = str(e)

    if content_lines is None:
        return findings, f"Unable to read file: {last_error}"

    filename_display = os.path.basename(filepath)

    for line_num, line in enumerate(content_lines, start=1):
        line_clean = line.strip()
        if not line_clean:
            continue

        for rule in SECRET_PATTERNS:
            match = rule["regex"].search(line_clean)
            if match:
                # Extract matched secret group if available, else full match
                matched_raw = match.group(1) if match.groups() else match.group(0)
                masked_val = mask_secret(matched_raw)

                findings.append({
                    "file": filepath,
                    "filename": filename_display,
                    "line": line_num,
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "masked_value": masked_val,
                    "description": rule["description"]
                })
                # Once matched by one rule on this line, proceed to next rule or line
                # (Allow multiple distinct rules if needed, but break to avoid duplicates)
                break

    return findings, None


def scan_directory(
    folder_path: str,
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Recursively scan a directory for exposed secrets.

    Returns:
        tuple: (results_list, summary_dict, errors_list)
    """
    normalized_path = os.path.abspath(os.path.normpath(folder_path))

    if not os.path.exists(normalized_path) or not os.path.isdir(normalized_path):
        raise ValueError(f"Invalid directory path: {normalized_path}")

    # Gather files to scan
    candidate_files: List[str] = []
    errors: List[str] = []

    for root, dirs, files in os.walk(normalized_path, topdown=True):
        # Exclude ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

        for file in files:
            full_path = os.path.join(root, file)
            if should_scan_file(full_path):
                candidate_files.append(full_path)

    total_files = len(candidate_files)
    all_findings: List[Dict[str, Any]] = []

    # Scan files
    for idx, filepath in enumerate(candidate_files, start=1):
        if progress_callback:
            progress_callback(idx, total_files, os.path.basename(filepath))

        findings, err = scan_file(filepath)
        if err:
            errors.append(f"{os.path.basename(filepath)}: {err}")
        else:
            all_findings.extend(findings)

    # Sort results by severity (HIGH, MEDIUM, LOW) then by file path
    severity_order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}
    all_findings.sort(key=lambda x: (severity_order.get(x["severity"], 99), x["file"], x["line"]))

    # Calculate summary metrics
    summary = {
        "files_scanned": total_files,
        "potential_secrets": len(all_findings),
        "high": sum(1 for item in all_findings if item["severity"] == SEVERITY_HIGH),
        "medium": sum(1 for item in all_findings if item["severity"] == SEVERITY_MEDIUM),
        "low": sum(1 for item in all_findings if item["severity"] == SEVERITY_LOW),
    }

    return all_findings, summary, errors


def export_to_csv(findings: List[Dict[str, Any]], output_filepath: str) -> None:
    """
    Export scan findings to a CSV file.
    CRITICAL: Never writes raw secrets, only masked values.
    """
    with open(output_filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Line", "Type", "Severity", "Masked Value"])

        for item in findings:
            writer.writerow([
                item["file"],
                item["line"],
                item["type"],
                item["severity"],
                item["masked_value"]
            ])
