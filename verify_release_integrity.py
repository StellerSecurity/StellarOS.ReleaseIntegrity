#!/usr/bin/env python3
"""Verify the published StellarOS release host against a pinned baseline."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BASELINE = ROOT / "trusted-site-baseline.json"
SAMPLES = ROOT / "large-file-samples.json"
ANCHOR = ROOT / "stellar-releases.ch-2026-10-25.sha256"
FULL_HASH_LIMIT = 50 * 1024 * 1024
CHUNK = 1024 * 1024
TIMEOUT = 90
USER_AGENT = "StellarOS-ReleaseIntegrity/1.0"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request(url: str, *, range_header: str | None = None):
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    if range_header:
        headers["Range"] = range_header
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT)


def hash_url(url: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with request(url) as response:
        while chunk := response.read(CHUNK):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def hash_range(url: str, start: int, length: int) -> tuple[str, int]:
    end = start + length - 1
    with request(url, range_header=f"bytes={start}-{end}") as response:
        if response.status != 206:
            raise RuntimeError(f"range request returned HTTP {response.status}")
        data = response.read(length + 1)
    if len(data) != length:
        raise RuntimeError(f"range returned {len(data)} bytes, expected {length}")
    return hashlib.sha256(data).hexdigest(), len(data)


def expected_anchor() -> str:
    for line in ANCHOR.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            digest, filename = line.split(maxsplit=1)
            if filename.strip() != "trusted-site-baseline.json":
                raise RuntimeError("anchor points to an unexpected file")
            return digest
    raise RuntimeError("anchor contains no checksum")


def main() -> int:
    failures: list[str] = []
    actual_baseline = sha256_file(BASELINE)
    if actual_baseline != expected_anchor():
        failures.append("trusted-site-baseline.json does not match the pinned anchor")

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    samples = json.loads(SAMPLES.read_text(encoding="utf-8"))["files"]
    origin = baseline["origin"].rstrip("/")

    checks: list[dict] = list(baseline["release_files"])
    for relative_path, metadata in baseline["site_files"].items():
        checks.append({"url": f"{origin}/{relative_path}", **metadata})

    for item in checks:
        url = item["url"]
        size = int(item["size"])
        try:
            if size <= FULL_HASH_LIMIT:
                digest, actual_size = hash_url(url)
                if actual_size != size:
                    failures.append(f"size mismatch: {url}: {actual_size} != {size}")
                if digest != item["sha256"]:
                    failures.append(f"SHA-256 mismatch: {url}")
            else:
                entry = samples.get(url)
                if not entry or int(entry["size"]) != size:
                    failures.append(f"missing or invalid sample metadata: {url}")
                    continue
                for sample in entry["samples"]:
                    digest, _ = hash_range(url, int(sample["offset"]), int(sample["length"]))
                    if digest != sample["sha256"]:
                        failures.append(f"sample mismatch at offset {sample['offset']}: {url}")
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            failures.append(f"request failed: {url}: {exc}")

    if failures:
        print("Integrity verification FAILED", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Integrity verification passed for {len(checks)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
