# Secret Scanner

A clean, lightweight, and defensive cybersecurity tool built with Python and Tkinter to scan source code and configuration files for **accidentally exposed secrets, credentials, API keys, passwords, and tokens**.

---

## 1. What the Project Does

Modern developers frequently push code to public or private Git repositories. A common and critical security mistake is **hardcoding sensitive secrets directly into source files or config files**.

**Secret Scanner** allows developers, security auditors, and students to select a project folder, crawl its files safely, and detect potential hardcoded secrets using pattern matching before pushing the code to GitHub.

---

## 2. Why Exposed Secrets Are a Cybersecurity Risk

Hardcoded credentials represent one of the most common vectors for initial access and cloud account takeover:

- **Automated Bot Scrapes:** Malicious bots continuously scrape public commits on GitHub within milliseconds of a push.
- **Cloud Account Takeover:** An exposed AWS Access Key or GCP service token allows attackers to spin up unauthorized cryptomining servers or exfiltrate sensitive customer databases.
- **Lateral Movement & Privilege Escalation:** Hardcoded database connection strings or internal service tokens allow an attacker who compromises one microservice to pivot across the entire infrastructure.
- **Defensive Purpose:** This tool is designed strictly for **defensive security and preventive auditing** to help developers catch accidental credential exposures prior to deployment.

---

## 3. How the Scanner Works

```text
[ Select Folder ]
       │
       ▼
[ Recursive Traversal ] ──(Filters out .git, node_modules, binary files)
       │
       ▼
[ Line-by-Line Regex Engine ] ──(Matches against 10 detection rules)
       │
       ▼
[ Secret Masking Engine ] ──(Obfuscates plain text: sk_live_******789)
       │
       ▼
[ GUI Results & CSV Export ] ──(Severity badges, summary counts, reports)
```

1. **Safe Traversal:** Recursively crawls the selected directory while skipping noise directories (`.git`, `node_modules`, `venv`, `__pycache__`) and large binary files.
2. **Chunk / Stream Analysis:** Reads text files line-by-line with encoding fallback (UTF-8 and Latin-1) without loading massive files into memory.
3. **Pattern Matching:** Evaluates 10 specialized regular expressions looking for known credential formats and variable assignments.
4. **Protective Masking:** Before displaying or saving any finding, the secret is obfuscated (e.g., `sk_live_123456789abcdef` becomes `sk_l***************cdef`). The raw secret is **never** printed to the UI or written to the report.

---

## 4. Technologies Used

- **Language:** Python 3.8+
- **GUI Framework:** Python `tkinter` & `ttk`
- **Regex Engine:** Python Standard `re` module
- **Data Export:** Python Standard `csv` module
- **Dependencies:** **Zero external pip packages** required.

---

## 5. Core Features

- **Multi-Extension Support:** Scans code files, configuration files, and environment files (`.py`, `.js`, `.ts`, `.env`, `.json`, `.yaml`, etc.).
- **Smart Binary Detection:** Inspects initial bytes for null characters to avoid freezing on binary files.
- **10 Core Secret Categories:** Detects AWS keys, GitHub tokens, JWTs, private keys, database connection strings, passwords, and API keys.
- **Severity Classification:** Categorizes findings into **HIGH**, **MEDIUM**, and **LOW** priority.
- **Privacy-Preserving Masking:** Keeps detected secrets secure even during demonstration.
- **Interactive Details Modal:** Double-click any finding in the GUI table to inspect the file path, line number, and rule explanation.
- **One-Click CSV Export:** Generates an audit report for remediation tracking.

---

## 6. Supported File Types

- **Code:** `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.php`, `.go`, `.rb`
- **Config & Data:** `.json`, `.yaml`, `.yml`, `.xml`, `.conf`, `.ini`, `.cfg`, `.toml`, `.txt`
- **Environment:** `.env`, `.env.local`, `.env.development`, `.env.production`

---

## 7. Detection Patterns & Severity

| Secret Type | Example Detection Pattern | Default Severity | Rationale |
| :--- | :--- | :---: | :--- |
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` | **HIGH** | Grants direct programmatic access to Amazon Web Services. |
| **GitHub Token** | `ghp_[A-Za-z0-9_]{36}` or `github_pat_...` | **HIGH** | Grants read/write access to repositories and source code. |
| **Private Key Header** | `-----BEGIN [TYPE] PRIVATE KEY-----` | **HIGH** | Cryptographic key compromise allows impersonation or decryption. |
| **Hardcoded Password** | `password = "..."` or `passwd: "..."` | **HIGH** | Authentication credentials directly exposed in code. |
| **API Key Assignment** | `api_key = "..."` or `apikey: "..."` | **HIGH** | High-privilege SaaS or third-party service credential. |
| **JSON Web Token (JWT)** | `ey...ey...ey...` (3-part structure) | **HIGH** | Live authorization bearer token. |
| **Database Connection** | `postgres://user:pass@host:port/db` | **HIGH** | Direct database access string containing embedded password. |
| **Secret Key Assignment**| `secret_key = "..."` or `client_secret = "..."` | **MEDIUM** | Application signing key or OAuth client secret. |
| **Access Token** | `access_token = "..."` | **MEDIUM** | Generic session or auth token assignment. |
| **Generic API Token** | `token = "..."` | **MEDIUM** | General token variable string. |

---

## 8. Project Structure

```text
secret-scanner/
│
├── main.py              # Tkinter GUI interface, table, and user controls
├── scanner.py           # Directory traversal, file reading, regex evaluation, masking
├── patterns.py          # 10 detection patterns, severity ratings, and rule metadata
├── requirements.txt     # Standard library documentation (zero pip installs)
├── .gitignore           # Ignores __pycache__, virtualenvs, and real .env files
├── README.md            # Comprehensive documentation
└── test_files/
    └── sample.py        # Demo file with safe fake credentials for testing
```

---

## 9. Installation & Prerequisites

1. Ensure Python 3.8 or higher is installed:
   ```bash
   python --version
   ```
2. Navigate to the project directory:
   ```bash
   cd secret-scanner
   ```
3. No external packages are required! Python's built-in standard library powers the entire application.

---

## 10. How to Run

Launch the application with Python:

```bash
python main.py
```

---

## 11. How to Test (Step-by-Step)

The project includes a ready-to-use test file ([`test_files/sample.py`](file:///c:/Users/DELL/Desktop/IOT-SURAJ/secret-scanner/test_files/sample.py)) filled with **safe, fake sample credentials** (such as standard AWS documentation dummy keys and RFC-compliant dummy JWTs).

1. Click **Select Folder**.
2. Browse to and select the `test_files` folder inside the `secret-scanner` directory.
3. Click **Start Scan**.
4. The application will scan `sample.py` and display all 10 potential secrets categorized with **HIGH** and **MEDIUM** severity.
5. Notice how all secret values are safely masked (e.g. `AKIA***************MPLE`).
6. Double-click any row to view its line number and description.
7. Click **Export Report** to save `secrets_report.csv`.

---

## 12. Example Output

### UI Summary Box:
```text
Files Scanned: 1 | Potential Secrets: 10 | High: 7 | Medium: 3 | Low: 0
```

### Table View:
| File | Line | Type | Severity | Detected Value (Masked) |
| :--- | :---: | :--- | :---: | :--- |
| `sample.py` | 8 | AWS Access Key | HIGH | `AKI****************PLE` |
| `sample.py` | 11 | GitHub Token | HIGH | `ghp****************jkl` |
| `sample.py` | 14 | Password | HIGH | `Fak****************26!` |
| `sample.py` | 17 | API Key | HIGH | `sk_****************ABC` |
| `sample.py` | 20 | JWT | HIGH | `eyJ****************54c` |
| `sample.py` | 23 | Database Connection String | HIGH | `pos****************_db` |
| `sample.py` | 33 | Private Key | HIGH | `-----BEGIN [ENCRYPTED/PRIVATE KEY]-----` |
| `sample.py` | 26 | Secret Key | MEDIUM | `sec****************210` |
| `sample.py` | 29 | Access Token | MEDIUM | `acc****************789` |
| `sample.py` | 32 | API Token | MEDIUM | `tok****************999` |

### Exported CSV File (`secrets_report.csv`):
```csv
File,Line,Type,Severity,Masked Value
C:\Users\...\test_files\sample.py,8,AWS Access Key,HIGH,AKI****************PLE
C:\Users\...\test_files\sample.py,11,GitHub Token,HIGH,ghp****************jkl
C:\Users\...\test_files\sample.py,14,Password,HIGH,Fak****************26!
```

---

## 13. Limitations

> [!WARNING]
> **Important Cybersecurity Disclaimer:**
> This tool uses pattern matching and can produce false positives or miss some secrets. A clean scan does not guarantee that a project contains no secrets.

1. **High-Entropy Random Strings:** Non-standard secret keys that do not follow known prefixes or variable naming conventions might not be matched.
2. **False Positives:** Variables named `password = "none"` or dummy test fixtures will be flagged because the scanner detects the pattern assignment.
3. **Obfuscated Code:** Secrets split across multiple variables (e.g. `part1 + part2`) or decoded from base64 at runtime will not be detected by static regex.

---

## 14. Future Improvements

- **Shannon Entropy Analysis:** Add Shannon entropy calculation to detect high-randomness strings even when no variable name matches.
- **Pre-Commit Git Hook:** Integrate as a `.git/hooks/pre-commit` script that automatically halts commits if a secret is found.
- **Custom Rule Builder:** Allow users to add custom regex rules via a JSON configuration file in the GUI.
- **Exclude Comments Option:** Provide an option to ignore single-line or multi-line comment blocks.
