#!/usr/bin/env python3
"""Anchor/Rust static review leads with explicit, non-certifying scope.

These checks do not confirm vulnerabilities. Confirmed findings require code
reasoning and, where possible, an original-binary runtime reproduction.
"""
from collections import Counter
import os
from pathlib import Path
import re

RULES = [
    ("incomplete-reconstruction", re.compile(r"todo!|unimplemented!|NotImplemented"), "high",
     "Incomplete handler or placeholder remains; establish whether this is intended deployed behavior."),
    ("unchecked-account", re.compile(r"\bUncheckedAccount\b"), "medium",
     "Validate owner, address, account layout and binding to the other accounts; an unchecked type is not itself a bug."),
    ("raw-account-info", re.compile(r"\bAccountInfo\b|remaining_accounts"), "info",
     "Review raw account validation and signer/writable privilege propagation."),
    ("cross-program-invocation", re.compile(r"\binvoke(?:_signed)?\s*\("), "medium",
     "Pin the CPI program and accounts; check signer seeds, privilege forwarding and nested-CPI effects."),
    ("panic-path", re.compile(r"\.unwrap\(\)|\.expect\(|panic!\s*\("), "low",
     "Check whether malformed accounts or attacker-controlled values can reach this panic path."),
    ("fallible-cast", re.compile(r"\bas\s+(?:u8|u16|u32|u64|usize|i64)\b"), "info",
     "Review narrowing/sign casts for truncation and domain assumptions."),
    ("init-if-needed", re.compile(r"\binit_if_needed\b"), "low",
     "Check reinitialization, zero-amount account creation and who pays for or controls the account."),
]


def review(workspace, capture_report=None, inspection=None):
    workspace = Path(workspace).resolve()
    capture_report = capture_report or {}
    inspection = inspection or {}
    leads = []
    # Skip build/vendor dirs by their path INSIDE the workspace; checking the
    # absolute path dropped every file when the workspace lived under e.g. ~/target/.
    files = []
    for dirpath, dirnames, filenames in os.walk(workspace, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in {"target", "vendor", ".git"}]
        files.extend(Path(dirpath) / name for name in filenames if name.endswith(".rs"))
    files.sort()
    for path in files:
        rel = path.relative_to(workspace).as_posix()
        lines = path.read_text(errors="replace").splitlines()
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            for rule, pattern, severity, recommendation in RULES:
                if not pattern.search(line):
                    continue
                if rule == "unchecked-account":
                    context = "\n".join(lines[max(0, number - 5):number - 1])
                    if "/// CHECK" in context:
                        continue  # an explicit justification still needs human review, but is not a bare lead
                leads.append({
                    "id": f"STATIC-{len(leads) + 1:04d}", "rule": rule,
                    "status": "UNCONFIRMED_REVIEW_LEAD", "severity_suggestion": severity,
                    "confidence": "static-pattern-only", "path": rel, "line": number,
                    "evidence": stripped[:300], "recommendation": recommendation,
                })
    counts = Counter(x["rule"] for x in leads)
    return {
        "schema_version": 1,
        "review_kind": "automated-static-pre-review",
        "status": "MANUAL_SECURITY_REVIEW_REQUIRED",
        "workspace": str(workspace),
        "rust_files_reviewed": len(files),
        "entrypoint_evidence": inspection.get("instruction_log_strings", []),
        "upgrade_authority_at_capture": capture_report.get("upgrade_authority"),
        "capture_slot": capture_report.get("slot"),
        "last_deploy_slot": capture_report.get("last_deploy_slot"),
        "confirmed_findings": [],
        "review_leads": leads,
        "summary": {
            "unconfirmed_leads": len(leads),
            "by_rule": dict(sorted(counts.items())),
            "confirmed_vulnerabilities": 0,
            "note": "Zero confirmed findings here means no runtime-confirmed findings were supplied, not that the program is secure.",
        },
        "required_manual_scope": [
            "Every instruction's signer, writable, owner, address and account-binding constraints",
            "PDA seeds, canonical bumps, initialization, close/revive and reinitialization behavior",
            "SOL/token accounting, checked arithmetic, rounding, snapshots and later deposits",
            "CPI program identity, account substitution, signer forwarding and nested CPI",
            "Token-2022 extensions, mint/freeze/permanent-delegate authorities and transfer hooks",
            "Lifecycle, expiration, admin/delegate powers, upgrade authority and external protocols",
            "Original-binary differential tests and PoCs for each claimed vulnerability",
        ],
    }


def audit_markdown(report, program_id, binary_sha256):
    lines = [
        "# Security review — automated pre-review", "",
        f"Target: `{program_id}`  ",
        f"Captured/rebuilt SHA-256: `{binary_sha256}`", "",
        "**Status: MANUAL_SECURITY_REVIEW_REQUIRED.** This file records static review leads only.",
        "No vulnerability is confirmed by these patterns, and no absence of vulnerabilities is claimed.",
        "A final audit must document code reasoning, affected instructions, preconditions, impact, and",
        "original-binary PoC evidence or an explicitly lower confidence level for each finding.", "",
        "## Summary", "",
        f"- Rust files scanned: {report['rust_files_reviewed']}",
        f"- Unconfirmed leads: {report['summary']['unconfirmed_leads']}",
        f"- Capture slot: {report.get('capture_slot')}",
        f"- Upgrade authority: `{report.get('upgrade_authority_at_capture')}`", "",
        "Byte identity ties source-level observations to the captured executable. It does not prove a",
        "security property, current mainnet state, off-chain policy, or safety of external programs.", "",
        "## Static review leads", "",
    ]
    if not report["review_leads"]:
        lines += ["No registered patterns fired. This is not a clean security result.", ""]
    for lead in report["review_leads"]:
        lines += [
            f"### {lead['id']} — {lead['rule']} ({lead['severity_suggestion']} review priority)", "",
            f"- Status: **{lead['status']}**; confidence: {lead['confidence']}",
            f"- Location: `{lead['path']}:{lead['line']}`",
            f"- Evidence: `{lead['evidence']}`",
            f"- Review: {lead['recommendation']}", "",
        ]
    lines += ["## Required manual scope", ""]
    lines += [f"- {x}" for x in report["required_manual_scope"]]
    lines += ["", "## Reviewer sign-off", "",
              "- Independent reviewer: _pending_",
              "- Entrypoint matrix completed: _pending_",
              "- Differential tests completed: _pending_",
              "- Findings reproduced on the captured original: _pending_",
              "- Residual risk and deployment recommendation: _pending_", ""]
    return "\n".join(lines)


def scope_markdown(report, program_id):
    lines = [
        "# Security review scope and evidence", "",
        f"Target: `{program_id}`. The review concerns the captured executable and its faithful source.",
        "It does not certify current mainnet state, frontends, off-chain signers, upgrade operators,",
        "external programs, or integrations not explicitly tested.", "",
        "## Evidence levels", "",
        "- `CONFIRMED_ON_ORIGINAL`: a bounded local execution reproduced the behavior on the captured binary.",
        "- `Source-level concern`: code reasoning exists but no dedicated runtime reproduction was performed.",
        "- `UNCONFIRMED_REVIEW_LEAD`: a static pattern needs analysis; it is not counted as a vulnerability.",
        "- A refuted hypothesis is not a vulnerability and must remain separate from confirmed findings.", "",
        "## Required entrypoint matrix", "",
    ]
    ixs = report.get("entrypoint_evidence") or []
    if ixs:
        lines += ["| Instruction | Constraints/effects reviewed | Runtime evidence | Result |",
                  "|---|---|---|---|"]
        lines += [f"| `{x}` | _pending_ | _pending_ | _pending_ |" for x in ixs]
    else:
        lines += ["No instruction-name evidence was supplied; the reviewer must recover and enumerate the dispatch surface."]
    lines += ["", "## Limitations", "",
              "Exact reconstruction preserves vulnerabilities; it does not remediate them.",
              "Passing a vulnerability PoC means the behavior was observed, not that the program is secure.",
              "This automated package is not an exhaustive professional audit or formal proof.", ""]
    return "\n".join(lines)
