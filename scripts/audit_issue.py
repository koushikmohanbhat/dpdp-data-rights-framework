"""Open or update the single tracking issue when the scheduled dependency audit fails.

    python scripts/audit_issue.py --summary audit-summary.md --run-url URL

Finds an open issue whose title is exactly TITLE. If there is one, it adds a comment; otherwise it creates one.
Uses the ``gh`` CLI with the workflow's token. Exit code 0 on success; any ``gh`` failure exits non-zero so the
run shows that the notification itself failed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

TITLE = "Scheduled dependency audit failed"
HOWTO = ("Fix the dependency, or add a time-limited, package-specific exception in .github/audit-policy.yml "
         "(docs/security.md#dependency-audit-gate).")


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()[:300]}")
    return out.stdout


def body(summary: str, run_url: str) -> str:
    return f"{summary.strip() or '(the audit produced no summary)'}\n\nRun: {run_url}\n\n{HOWTO}\n"


def open_or_update(summary: str, run_url: str, run=gh) -> str:
    """Comment on the open tracking issue, or create it. Returns what was done."""
    found = json.loads(run("issue", "list", "--state", "open", "--search", f'in:title "{TITLE}"',
                           "--json", "number,title", "--limit", "50") or "[]")
    exact = [i for i in found if i.get("title") == TITLE]          # search is fuzzy; match the title exactly
    text = body(summary, run_url)
    if exact:
        n = str(min(i["number"] for i in exact))
        run("issue", "comment", n, "--body", text)
        return f"commented on #{n}"
    run("issue", "create", "--title", TITLE, "--body", text)
    return "created"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--summary", required=True, help="file with the gate's output")
    ap.add_argument("--run-url", required=True)
    a = ap.parse_args(argv)
    p = Path(a.summary)
    summary = p.read_text() if p.exists() else ""
    try:
        print(open_or_update(summary, a.run_url))
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
