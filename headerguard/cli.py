"""Check saved response-header data against a small defensive baseline."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any

REQUIRED = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def review(document: dict[str, Any]) -> dict[str, Any]:
    headers = document.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("'headers' must be a JSON object")
    normalized = {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}
    findings = []
    for key, label in REQUIRED.items():
        value = normalized.get(key, "")
        if not value:
            findings.append({"severity": "warning", "header": label, "finding": "missing"})
        elif key == "x-content-type-options" and value.lower() != "nosniff":
            findings.append({"severity": "warning", "header": label, "finding": "expected nosniff"})
        elif key == "strict-transport-security":
            if "max-age=" not in value.lower():
                findings.append({"severity": "warning", "header": label, "finding": "max-age directive not found"})
            elif "max-age=0" in value.lower().replace(" ", ""):
                findings.append({"severity": "warning", "header": label, "finding": "max-age is zero"})
        elif key == "content-security-policy":
            lowered = value.lower()
            for directive in ("object-src", "base-uri"):
                if directive not in lowered:
                    findings.append({"severity": "note", "header": label, "finding": f"consider an explicit {directive} directive"})
    return {
        "target_label": str(document.get("target", "unspecified")),
        "headers_reviewed": len(headers),
        "findings": findings,
        "result": "review" if findings else "baseline-present",
        "scope": "Saved header data only; no network requests were made.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Review saved HTTP response headers locally.")
    parser.add_argument("input", type=Path, help="JSON file with an optional target label and headers object")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("top-level JSON value must be an object")
        result = review(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
