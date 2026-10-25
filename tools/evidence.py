#!/usr/bin/env python3
"""Deterministic build-input manifests shared by builds and finalization.

Every file is hashed unless it is explicitly build output, dependency vendor
content (manifested separately), or named non-build evidence. Extensions are not
used as a proxy for what can affect compilation.
"""
import hashlib
import os
from pathlib import Path

ALGORITHM = "solopen-source-tree-v2"
SKIP_ANY = {"target", "vendor", ".git", "__pycache__", "node_modules"}
SKIP_ROOT = {
    ".build", "build", "dist", "run", "runs", "capture", "reverse", "release",
    # Published comparison/security material is packaged separately, not as
    # reconstruction source that could hide or inject deployed bytes.
    "evidence", "binaries", "audit", "docs", "repro", "clank",
}


def skipped(rel):
    """True for workspace-relative paths the manifest does not cover. The AI
    loop uses the same rule, so it can never edit a file that isn't hashed."""
    rel = Path(rel)
    return any(part in SKIP_ANY for part in rel.parts) or \
        (bool(rel.parts) and rel.parts[0] in SKIP_ROOT)


def source_files(root):
    root = Path(root).resolve()
    files = []

    # Prune before descending: vendor and build output can contain hundreds of
    # thousands of files and must not be traversed merely to be excluded.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        rel_dir = base.relative_to(root)
        dirnames[:] = [name for name in dirnames if not skipped(rel_dir / name)]
        for name in filenames:
            if name.endswith(".solopen-tmp"):
                continue
            rel = rel_dir / name
            if skipped(rel):
                continue
            path = base / name
            if path.is_file():
                files.append((rel.as_posix(), path))
    return sorted(files)


def source_manifest(root):
    """Hash content and paths, not mtimes or absolute host locations."""
    entries = []
    tree = hashlib.sha256()
    tree.update(ALGORITHM.encode() + b"\x00")
    for rel, path in source_files(root):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        entries.append({"path": rel, "bytes": len(raw), "sha256": digest})
        tree.update(rel.encode() + b"\x00")
        tree.update(str(len(raw)).encode() + b"\x00")
        tree.update(raw)
        tree.update(b"\x00")
    return {"algorithm": ALGORITHM, "tree_sha256": tree.hexdigest(), "files": entries}


def same_source(manifest, root):
    current = source_manifest(root)
    return current["algorithm"] == manifest.get("algorithm") and \
        current["tree_sha256"] == manifest.get("tree_sha256") and \
        current["files"] == manifest.get("files")
