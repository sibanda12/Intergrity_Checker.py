# Intergrity_Checker.py
# File Integrity Checker (FIC)

A lightweight, fast **File Integrity Checker** written in Python that:
- Creates a **cryptographic baseline** (hashes) for all files in a folder.
- Detects **modified, added, and deleted** files by comparing to the baseline.
- Outputs a clean **human-readable report** and can also save a **JSON report**.

Great for **incident response, forensics basics, and system auditing**.

---

## ✨ Features
- Hash algorithms: `SHA256` (default), `SHA1`, `MD5`
- Include/exclude using glob patterns
- Optional hidden files, symlink following, and max-size filtering
- Concurrent hashing (fast on big trees)
- JSON diff export and optional auto-update of baseline
- Works cross-platform (Linux, macOS, Windows)

---

## 🧰 Requirements
- Python 3.8+

No external libraries needed (uses the standard library).

---

## 🚀 Quickstart

### 1) Create a baseline
```bash
python integrity_checker.py init /path/to/folder
