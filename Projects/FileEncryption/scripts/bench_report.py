#!/usr/bin/env python3
"""Turn a Google Benchmark JSON report into a relative-throughput markdown summary.

Absolute throughput on a shared CI runner says more about which host the job landed on than about the
code, so the number reported here is the pipeline's throughput as a fraction of raw OpenSSL AES-256-GCM
measured in the same process, in the same job. That ratio is stable across hardware.

Usage:
    python3 bench_report.py benchmark.json >> "$GITHUB_STEP_SUMMARY"
"""

import json
import sys

GIB = 1024.0**3

RAW_16K = "BenchRawEvpEncrypt/16384"
RAW_64K = "BenchRawEvpEncrypt/65536"
RAW_CHUNKED = "BenchRawEvpChunked"
PIPE_ENC = "BenchPipelineEncrypt"
PIPE_DEC = "BenchPipelineDecrypt"
ARGON2 = "BenchArgon2id"

THROUGHPUT_ROWS = [
    (RAW_16K, "Raw OpenSSL EVP, 16 KiB chunks", "cross-check against `openssl speed`"),
    (RAW_64K, "Raw OpenSSL EVP, 64 KiB chunks", "streaming, one nonce for the whole run"),
    (RAW_CHUNKED, "Raw OpenSSL EVP, chunked AEAD", "baseline: per-chunk nonce, AAD and tag"),
    (PIPE_ENC, "AesGcm pipeline, encrypt", "256 MiB, tmpfs"),
    (PIPE_DEC, "AesGcm pipeline, decrypt", "256 MiB, tmpfs, single pass"),
]

RATIO_ROWS = [
    (PIPE_ENC, RAW_CHUNKED, "Encrypt pipeline / raw EVP"),
    (PIPE_DEC, RAW_CHUNKED, "Decrypt pipeline / raw EVP"),
]


def load(path):
    """Index every run by name, then by aggregate. A plain (non-aggregate) run is filed under "".

    A run registered with Iterations(n) is reported as "<name>/iterations:n", and a run measured with a
    single repetition carries no aggregates at all, so neither the exact name nor the "median" key can be
    assumed to be present.
    """
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)

    index = {}

    for entry in report.get("benchmarks", []):
        name = entry.get("run_name")

        if name:
            index.setdefault(name, {})[entry.get("aggregate_name") or ""] = entry

    return report.get("context", {}), index


def resolve(index, name):
    """Match a run exactly, or by the harness-added "/..." suffix when that is unambiguous."""
    if name in index:
        return index[name]

    matches = [key for key in index if key.startswith(name + "/")]

    return index[matches[0]] if len(matches) == 1 else None


def field(index, name, aggregate, key):
    """Read one field, returning None when the benchmark or the field is absent."""
    runs = resolve(index, name)

    if runs is None:
        return None

    entry = runs.get(aggregate)

    # A single-repetition run has no aggregates; its one measurement stands in for the median
    if entry is None and aggregate == "median":
        entry = runs.get("")

    return None if entry is None else entry.get(key)


def has_aggregates(index):
    """True when the report was produced with more than one repetition."""
    return any(key for runs in index.values() for key in runs)


def gibs(index, name, aggregate="median"):
    """Median throughput in GiB/s."""
    value = field(index, name, aggregate, "bytes_per_second")

    return None if value is None else value / GIB


def throughput_table(index):
    lines = [
        "| Benchmark | Median | Stddev | CV | Notes |",
        "| --- | ---: | ---: | ---: | --- |",
    ]

    for name, label, note in THROUGHPUT_ROWS:
        median = gibs(index, name)

        if median is None:
            lines.append(f"| {label} | _missing_ | | | {note} |")
            continue

        stddev = gibs(index, name, "stddev")
        cv = field(index, name, "cv", "bytes_per_second")

        stddev_txt = "" if stddev is None else f"{stddev:.3f} GiB/s"
        cv_txt = "" if cv is None else f"{cv * 100:.1f}%"

        lines.append(f"| {label} | **{median:.3f} GiB/s** | {stddev_txt} | {cv_txt} | {note} |")

    return lines


def ratio_table(index):
    lines = [
        "| Metric | Value |",
        "| --- | ---: |",
    ]

    missing = False

    for numerator, denominator, label in RATIO_ROWS:
        top = gibs(index, numerator)
        bottom = gibs(index, denominator)

        if top is None or bottom is None or bottom == 0:
            lines.append(f"| {label} | _missing_ |")
            missing = True
            continue

        lines.append(f"| {label} | **{top / bottom * 100:.1f}%** |")

    argon2_ms = field(index, ARGON2, "median", "real_time")

    if argon2_ms is None:
        lines.append("| Argon2id key derivation | _missing_ |")
        missing = True
    else:
        unit = field(index, ARGON2, "median", "time_unit") or "ms"
        lines.append(f"| Argon2id key derivation (m=512 MiB, t=4, p=4) | {argon2_ms:.0f} {unit} |")

    return lines, missing


def cross_check(index):
    """The 16 KiB in-process baseline should land close to `openssl speed`'s 16384-byte column."""
    value = gibs(index, RAW_16K)

    if value is None:
        return []

    return [
        "",
        f"In-process 16 KiB baseline: **{value * GIB / 1e9:.2f} GB/s** "
        "(compare with the 16384-byte column of `openssl speed -evp aes-256-gcm` above; "
        "a large gap means the two are not measuring the same code path).",
    ]


def main():
    if len(sys.argv) != 2:
        print("usage: bench_report.py <benchmark.json>", file=sys.stderr)
        return 2

    try:
        context, index = load(sys.argv[1])
    except (OSError, ValueError) as error:
        print(f"Could not read benchmark report: {error}", file=sys.stderr)
        return 1

    out = ["### Relative throughput", ""]
    out += ratio_table(index)[0]
    out += cross_check(index)
    out += ["", "<details><summary>Absolute figures (host dependent, not comparable across runs)</summary>", ""]
    out += throughput_table(index)

    if context.get("library_build_type"):
        out += ["", f"Build type: `{context['library_build_type']}`."]

    if context.get("cpu_scaling_enabled"):
        out += ["", "> CPU frequency scaling was enabled on this runner; timings are noisier than usual."]

    if not has_aggregates(index):
        out += ["", "> Single repetition: the figures above are one measurement each, not medians."]

    out += ["", "</details>", ""]

    print("\n".join(out))

    return 0


if __name__ == "__main__":
    sys.exit(main())
