"""
patterns.py - Secret Detection Pattern Definitions

Defines regular expression patterns, secret categories, and severity ratings
used by Secret Scanner to identify exposed credentials, tokens, and keys.
"""

import re
from typing import List, Dict, Any

# Severity Constants
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"


# List of 10 core regex detection rules
SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "AWS Access Key ID",
        "type": "AWS Access Key",
        "severity": SEVERITY_HIGH,
        "description": "Amazon Web Services 20-character Access Key identifier",
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    },
    {
        "name": "GitHub Personal Access Token",
        "type": "GitHub Token",
        "severity": SEVERITY_HIGH,
        "description": "GitHub classic personal access token or fine-grained token",
        "regex": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b")
    },
    {
        "name": "Private Key Header",
        "type": "Private Key",
        "severity": SEVERITY_HIGH,
        "description": "Cryptographic private key file header (RSA, OpenSSH, EC)",
        "regex": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")
    },
    {
        "name": "Hardcoded Password",
        "type": "Password",
        "severity": SEVERITY_HIGH,
        "description": "Assignment of plaintext password in source code or config",
        "regex": re.compile(r'''(?i)\b(?:[a-z0-9_]*_)?(?:password|passwd|pwd)\b\s*[:=]\s*["']([^"'\s]{6,64})["']''')
    },
    {
        "name": "API Key Assignment",
        "type": "API Key",
        "severity": SEVERITY_HIGH,
        "description": "Explicit assignment to an api_key or apikey variable",
        "regex": re.compile(r'''(?i)\b(?:[a-z0-9_]*_)?(?:api[_-]?key|apikey)\b\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''')
    },
    {
        "name": "JSON Web Token (JWT)",
        "type": "JWT",
        "severity": SEVERITY_HIGH,
        "description": "Three-part base64 encoded JSON Web Token structure",
        "regex": re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
    },
    {
        "name": "Database Connection String",
        "type": "Database Connection String",
        "severity": SEVERITY_HIGH,
        "description": "Database URI containing embedded credentials",
        "regex": re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+)")
    },
    {
        "name": "Secret Key Assignment",
        "type": "Secret Key",
        "severity": SEVERITY_MEDIUM,
        "description": "Secret key or client secret variable assignment",
        "regex": re.compile(r'''(?i)\b(?:[a-z0-9_]*_)?(?:secret[_-]?key|client[_-]?secret)\b\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''')
    },
    {
        "name": "Access Token Assignment",
        "type": "Access Token",
        "severity": SEVERITY_MEDIUM,
        "description": "Access token or auth token variable assignment",
        "regex": re.compile(r'''(?i)\b(?:[a-z0-9_]*_)?(?:access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,128})["']''')
    },
    {
        "name": "Generic API Token",
        "type": "API Token",
        "severity": SEVERITY_MEDIUM,
        "description": "Generic token assignment or service token string",
        "regex": re.compile(r'''(?i)\b(?:[a-z0-9_]*_)?(?:api[_-]?token|service[_-]?token|token)\b\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''')
    }
]
