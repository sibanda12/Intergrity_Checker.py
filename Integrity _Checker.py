#!/usr/bin/env python3
"""
File Integrity Checker (FIC)
Author: Mandisi Sibanda
License: MIT

Description:
  - Create a cryptographic baseline (hashes) for all files in a folder
  - Compare current state to that baseline to detect modified/added/deleted files
  - Save human-readable and JSON reports
  - Practical for incident response & forensics basics
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import fnmatch
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ---- Constants ---------------------------------------------------------------

CHUNK_SIZE = 1024 * 1024  # 1 MiB reads
DEFAULT_DB_NAME = ".integrity_db.json"

SUPPORTED_ALGOS = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
    "md5": hashlib.md5,
}

# ---- Data Models -------------------------------------------------------------

@dataclass
class FileRecord:
    relpath: str
    hash: str
    size: int
    mtime: float

@dataclass
class Baseline:
    root: str
    algo: str
    created_at: float
    records: Dict[str, FileRecord]  # key: relpath

    def to_json(self) -> dict:
        return {
            "root": self.root,
            "algo": self.algo,
            "created_at": self.created_at,
            "records": {k: asdict(v) for k, v in self.records.items()},
        }

    @staticmethod
    def from_json(d: dict) -> "Baseline":
        recs = {k: FileRecord(**v) for k, v in d["records"].items()}
        return Baseline(root=d["root"], algo=d["algo"], created_at=d["created_at"], records=recs)

# ---- Helpers ----------------------------------------------------------------

def norm_relpath(root: Path, p: Path) -> str:
    return str(p.resolve().absolute().relative_to(root.resolve().absolute())).replace(os.sep, "/")

def is_hidden(relpath: Path) -> bool:
    # Heuristic: any path segment starting with '.' counts as hidden (cross-platform)
    return any(part.startswith(".") for part in relpath.parts if part not in (os.sep, "/"))

def hash_file(path: Path, algo_name: str) -> Tuple[str, int, float]:
    hasher = SUPPORTED_ALGOS[algo_name]()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        mtime = 0.0  # disappeared mid-read
    return hasher.hexdigest(), size, mtime

def iter_files(
    root: Path,
    include: List[str],
    exclude: List[str],
    include_hidden: bool,
    follow_symlinks: bool,
    max_size_mb: Optional[int],
) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirpath_p = Path(dirpath)

        # Filter hidden directories if needed
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

        for fn in filenames:
            p = dirpath_p / fn

            # Skip if symlink and we're not following
            try:
                if not follow_symlinks and p.is_symlink():
                    continue
            except OSError:
                continue

            rel = p.relative_to(root)
            # Filter hidden files
            if not include_hidden and is_hidden(rel):
                continue

            # Max size filter
            if max_size_mb is not None:
                try:
                    if p.stat().st_size > max_size_mb * 1024 * 1024:
                        continue
                except OSError:
                    continue

            rel_str = str(rel).replace(os.sep, "/")
            # Include patterns (if provided, must match at least one)
            if include and not any(fnmatch.fnmatch(rel_str, pat) for pat in include):
                continue
            # Exclude patterns (if any match, skip)
            if exclude and any(fnmatch.fnmatch(rel_str, pat) for pat in exclude):
                continue

            yield p

def build_baseline(
    root: Path,
    algo: str,
    include: List[str],
    exclude: List[str],
    include_hidden: bool,
    follow_symlinks: bool,
    workers: int,
    max_size_mb: Optional[int],
) -> Baseline:
    files = list(iter_files(root, include, exclude, include_hidden, follow_symlinks, max_size_mb))
    records: Dict[str, FileRecord] = {}

    # Hash concurrently (I/O bound)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(hash_file, f, algo): f for f in files}
        for fut in cf.as_completed(futs):
            f = futs[fut]
            try:
                hexdigest, size, mtime = fut.result()
            except Exception as e:
                print(f"[WARN] Failed to hash {f}: {e}", file=sys.stderr)
                continue
            rel = norm_relpath(root, f)
            records[rel] = FileRecord(relpath=rel, hash=hexdigest, size=size, mtime=mtime)

    return Baseline(root=str(root.resolve()), algo=algo, created_at=time.time(), records=records)

def save_baseline(baseline: Baseline, db_path: Path) -> None:
    db_path.write_text(json.dumps(baseline.to_json(), indent=2), encoding="utf-8")

def load_baseline(db_path: Path) -> Baseline:
    return Baseline.from_json(json.loads(db_path.read_text(encoding="utf-8")))

def compare(baseline: Baseline, current: Baseline) -> dict:
    before = baseline.records
    after = current.records

    modified: List[str] = []
    added: List[str] = []
    deleted: List[str] = []

    for rel, rec in after.items():
        if rel not in before:
            added.append(rel)
        else:
            if rec.hash != before[rel].hash:
                modified.append(rel)

    for rel in before.keys():
        if rel not in after:
            deleted.append(rel)

    return {
        "root": current.root,
        "algo": current.algo,
        "generated_at": time.time(),
        "summary": {
            "before_count": len(before),
            "after_count": len(after),
            "modified": len(modified),
            "added": len(added),
            "deleted": len(deleted),
        },
        "modified": sorted(modified),
        "added": sorted(added),
        "deleted": sorted(deleted),
    }

def human_report(diff: dict, verbose: bool = False) -> str:
    s = diff["summary"]
    lines = []
    lines.append("==== File Integrity Check Report ====")
    lines.append(f"Root       : {diff['root']}")
    lines.append(f"Algorithm  : {diff['algo']}")
    lines.append(f"Before     : {s['before_count']} files")
    lines.append(f"After      : {s['after_count']} files")
    lines.append(f"Modified   : {s['modified']}")
    lines.append(f"Added      : {s['added']}")
    lines.append(f"Deleted    : {s['deleted']}")
    lines.append("-------------------------------------")

    # Sections
    lines.append("Modified files:" if (verbose or s["modified"]) else "")
    if verbose or s["modified"]:
        if s["modified"]:
            lines.extend(f"  • {p}" for p in diff["modified"])
        else:
            lines.append("  (none)")
        lines.append("")

    lines.append("Added files:" if (verbose or s["added"]) else "")
    if (verbose or s["added"]):
        if s["added"]:
            lines.extend(f"  • {p}" for p in diff["added"])
        else:
            lines.append("  (none)")
        lines.append("")

    lines.append("Deleted files:" if (verbose or s["deleted"]) else "")
    if (verbose or s["deleted"]):
        if s["deleted"]:
            lines.extend(f"  • {p}" for p in diff["deleted"])
        else:
            lines.append("  (none)")
        lines.append("")

    # Remove possible empty strings (if not verbose and zeros)
    return "\n".join([ln for ln in lines if ln != ""])

def ensure_db_path(target_root: Path, db_arg: Optional[Path]) -> Path:
    if db_arg:
        return db_arg
    return target_root / DEFAULT_DB_NAME

def parse_patterns(patterns: Optional[List[str]]) -> List[str]:
    return patterns if patterns else []

# ---- CLI --------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="integrity_checker",
        description="File Integrity Checker: create and verify cryptographic baselines of folders.",
    )
    parser.add_argument("--algo", default="sha256", choices=list(SUPPORTED_ALGOS.keys()),
                        help="Hash algorithm (default: sha256)")
    parser.add_argument("--include", nargs="*", default=[], help="Glob patterns to include (relative paths)")
    parser.add_argument("--exclude", nargs="*", default=[], help="Glob patterns to exclude (relative paths)")
    parser.add_argument("--hidden", action="store_true", help="Include hidden files/folders (dotfiles)")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during traversal")
    parser.add_argument("--max-size-mb", type=int, default=None, help="Skip files larger than this size (MB)")
    parser.add_argument("--workers", type=int, default=8, help="Thread workers for hashing (I/O bound)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose reports (list empty sections)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="Create a new baseline for a folder")
    p_init.add_argument("folder", type=str, help="Target folder to baseline")
    p_init.add_argument("--db", type=str, default=None, help=f"Baseline file path (default: {DEFAULT_DB_NAME} in folder)")

    # check
    p_check = sub.add_parser("check", help="Compare folder to baseline")
    p_check.add_argument("folder", type=str, help="Target folder")
    p_check.add_argument("--db", type=str, default=None, help=f"Baseline file path (default: {DEFAULT_DB_NAME} in folder)")
    p_check.add_argument("--save-report", type=str, default=None, help="Save diff JSON to this path")
    p_check.add_argument("--auto-update", action="store_true", help="Update baseline with current state after check")

    # scan (no baseline; just print current hashes)
    p_scan = sub.add_parser("scan", help="Scan folder and print current file hashes (no baseline)")
    p_scan.add_argument("folder", type=str, help="Target folder")

    # print-db
    p_print = sub.add_parser("print-db", help="Print baseline summary")
    p_print.add_argument("--db", type=str, required=True, help="Baseline file path")

    args = parser.parse_args(argv)

    folder = None
    if args.cmd in ("init", "check", "scan"):
        folder = Path(args.folder).resolve()
        if not folder.exists() or not folder.is_dir():
            print(f"[ERROR] Folder not found or not a directory: {folder}", file=sys.stderr)
            return 2

    include = parse_patterns(args.include)
    exclude = parse_patterns(args.exclude)

    try:
        if args.cmd == "init":
            db_path = ensure_db_path(folder, Path(args.db).resolve() if args.db else None)
            baseline = build_baseline(folder, args.algo, include, exclude, args.hidden, args.follow_symlinks, args.workers, args.max_size_mb)
            save_baseline(baseline, db_path)
            print(f"[OK] Baseline created with {len(baseline.records)} files")
            print(f"[OK] Saved to: {db_path}")
            return 0

        elif args.cmd == "check":
            db_path = ensure_db_path(folder, Path(args.db).resolve() if args.db else None)
            if not db_path.exists():
                print(f"[ERROR] Baseline not found: {db_path}", file=sys.stderr)
                return 3
            baseline = load_baseline(db_path)
            # Always use the baseline algo unless the user explicitly changes it
            algo = args.algo or baseline.algo
            current = build_baseline(folder, algo, include, exclude, args.hidden, args.follow_symlinks, args.workers, args.max_size_mb)
            diff = compare(baseline, current)
            print(human_report(diff, verbose=args.verbose))
            if args.save_report:
                Path(args.save_report).write_text(json.dumps(diff, indent=2), encoding="utf-8")
                print(f"[OK] JSON report saved to: {args.save_report}")
            if args.auto_update:
                save_baseline(current, db_path)
                print(f"[OK] Baseline updated at: {db_path}")
            return 0

        elif args.cmd == "scan":
            # Print relpath and hash for current state (no baseline)
            files = list(iter_files(folder, include, exclude, args.hidden, args.follow_symlinks, args.max_size_mb))
            for f in files:
                try:
                    hexdigest, size, mtime = hash_file(f, args.algo)
                except Exception as e:
                    print(f"[WARN] Failed to hash {f}: {e}", file=sys.stderr)
                    continue
                rel = norm_relpath(folder, f)
                print(json.dumps({"path": rel, "hash": hexdigest, "size": size, "mtime": mtime}))
            return 0

        elif args.cmd == "print-db":
            db_path = Path(args.db).resolve()
            if not db_path.exists():
                print(f"[ERROR] Baseline not found: {db_path}", file=sys.stderr)
                return 3
            baseline = load_baseline(db_path)
            print(json.dumps({
                "root": baseline.root,
                "algo": baseline.algo,
                "created_at": baseline.created_at,
                "count": len(baseline.records),
            }, indent=2))
            return 0

        else:
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    sys.exit(main())
