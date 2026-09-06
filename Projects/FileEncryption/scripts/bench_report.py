#!/usr/bin/env python3
"""Turn a Google Benchmark JSON report into a markdown summary of pipeline efficiency.

Absolute throughput on a shared CI runner says more about which host the job landed on than about the
code, so what is reported here is a ratio. Which ratio matters:

The pipeline reads 256 MiB and writes 256 MiB. A loop that encrypts one 64 KiB buffer over and over
reads and writes nothing at all, because after the first round its whole working set sits in the cache.
Dividing the first by the second produces a real number that means almost nothing about the pipeline:
most of the gap is main memory, which the numerator has to touch and the denominator does not.

So the headline ratio is taken against BenchFileCopy, which performs the same reads and the same writes
with no crypto whatsoever. Nothing can go faster than that, so the ratio is a genuine efficiency, and
what it leaves out is exactly the cost of encryption plus the pipeline's own machinery.

That ratio is not stable across hardware either, and no ratio here is: it is roughly a function of
AES throughput divided by memory bandwidth, and those two do not advance together. A machine with VAES
roughly doubles the first and leaves the second alone. Read these numbers against the run they came
from, never against a number written down on a different machine.

Usage:
    python3 bench_report.py benchmark.json >> "$GITHUB_STEP_SUMMARY"
"""

import json
import sys

GIB = 1024.0**3

UNIT_MS = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1000.0}

RAW_16K = "BenchRawEvpEncrypt/16384"
RAW_64K = "BenchRawEvpEncrypt/65536"
RAW_CHUNKED = "BenchRawEvpChunked"
RAW_STREAMING = "BenchRawEvpStreaming"
FILE_COPY = "BenchFileCopy"
PIPE_ENC = "BenchPipelineEncrypt"
PIPE_ENC_SYNC = "BenchPipelineEncryptSync"
PIPE_DEC = "BenchPipelineDecrypt"
ARGON2 = "BenchArgon2id"

THROUGHPUT_ROWS = [
    (RAW_16K, "Raw OpenSSL EVP, 16 KiB chunks", "cross-check against `openssl speed`"),
    (RAW_64K, "Raw OpenSSL EVP, 64 KiB chunks", "streaming, one nonce for the whole run"),
    (RAW_CHUNKED, "Raw EVP, chunked AEAD, cache resident", "64 KiB buffer reused every round"),
    (RAW_STREAMING, "Raw EVP, chunked AEAD, memory resident", "256 MiB working set, same work"),
    (FILE_COPY, "File copy, no crypto", "the floor: same reads and writes"),
    (PIPE_ENC, "AesGcm pipeline, encrypt", "256 MiB, tmpfs, asynchronous write"),
    (PIPE_ENC_SYNC, "AesGcm pipeline, encrypt", "256 MiB, tmpfs, synchronous write"),
    (PIPE_DEC, "AesGcm pipeline, decrypt", "256 MiB, tmpfs, single pass"),
]

EFFICIENCY_ROWS = [
    (PIPE_ENC, FILE_COPY, "Encrypt pipeline / file-copy floor"),
    (PIPE_DEC, FILE_COPY, "Decrypt pipeline / file-copy floor"),
]

# Kept for continuity with older runs, and labelled for what it is rather than as an efficiency
LEGACY_ROWS = [
    (PIPE_ENC, RAW_CHUNKED, "Encrypt pipeline / cache-resident crypto"),
    (PIPE_DEC, RAW_CHUNKED, "Decrypt pipeline / cache-resident crypto"),
]

TIMELINE_ROWS = [
    (FILE_COPY, "File copy, no crypto", "the floor: the reads and the writes alone"),
    (RAW_CHUNKED, "Crypto alone, cache resident", "what a chunk costs once fread has delivered it"),
]

TIMELINE_MEASURED_ROWS = [
    (PIPE_ENC, "Pipeline, encrypt, async write", "measured"),
    (PIPE_ENC_SYNC, "Pipeline, encrypt, sync write", "measured"),
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


def millis(index, name, aggregate="median"):
    """Median wall time for one iteration, in milliseconds.

    Every pipeline-sized benchmark processes exactly one kBenchSize pass per iteration, so this is
    directly comparable across them without the report having to know what kBenchSize is.
    """
    value = field(index, name, aggregate, "real_time")

    if value is None:
        return None

    scale = UNIT_MS.get(field(index, name, aggregate, "time_unit") or "ms")

    return None if scale is None else value * scale


def ratio_row(index, numerator, denominator, label):
    """One "A / B" percentage row, or a placeholder when either side is missing."""
    top = gibs(index, numerator)
    bottom = gibs(index, denominator)

    if top is None or bottom is None or bottom == 0:
        return f"| {label} | _missing_ |", True

    return f"| {label} | **{top / bottom * 100:.1f}%** |", False


def efficiency_table(index):
    lines = [
        "| Metric | Value |",
        "| --- | ---: |",
    ]

    missing = False

    for numerator, denominator, label in EFFICIENCY_ROWS:
        line, gap = ratio_row(index, numerator, denominator, label)

        lines.append(line)
        missing = missing or gap

    fast = gibs(index, PIPE_ENC)
    slow = gibs(index, PIPE_ENC_SYNC)

    if fast is None or slow is None or slow == 0:
        lines.append("| Asynchronous write vs synchronous | _missing_ |")
        missing = True
    else:
        lines.append(f"| Asynchronous write vs synchronous | **{(fast / slow - 1) * 100:+.1f}%** |")

    argon2_ms = millis(index, ARGON2)

    if argon2_ms is None:
        lines.append("| Argon2id key derivation | _missing_ |")
        missing = True
    else:
        lines.append(f"| Argon2id key derivation (m=512 MiB, t=4, p=4) | {argon2_ms:.0f} ms |")

    return lines, missing


def timeline_table(index):
    """Break one 256 MiB pass into the parts it is made of, in milliseconds.

    The crypto term is the cache-resident figure, not the memory-resident one. A chunk is encrypted in
    place in the 64 KiB buffer fread has just filled, so it is already in the cache by then; charging
    the memory-resident figure here would count the same traffic twice, once in the copy and once in
    the crypto. The memory-resident run is a diagnostic about the old baseline, not a term in this sum.
    """
    lines = [
        "| Stage | Time | What it is |",
        "| --- | ---: | --- |",
    ]

    def row(name, label, note):
        value = millis(index, name)

        return f"| {label} | {'_missing_' if value is None else f'{value:.0f} ms'} | {note} |"

    for name, label, note in TIMELINE_ROWS:
        lines.append(row(name, label, note))

    floor = millis(index, FILE_COPY)
    crypto = millis(index, RAW_CHUNKED)

    if floor is not None and crypto is not None:
        lines.append(
            f"| Floor + crypto, no overlap | {floor + crypto:.0f} ms | "
            "the serial bound the writer thread exists to beat |"
        )

    for name, label, note in TIMELINE_MEASURED_ROWS:
        lines.append(row(name, label, note))

    lines.append(row(RAW_STREAMING, "Crypto alone, memory resident", "diagnostic only, see below"))

    return lines


def cache_note(index):
    """State the cache effect outright, since it is the thing the old ratio was silently measuring."""
    cached = gibs(index, RAW_CHUNKED)
    streamed = gibs(index, RAW_STREAMING)

    if cached is None or streamed is None or streamed == 0:
        return []

    return [
        "",
        f"Cache-resident crypto measures **{cached / streamed:.1f}x** the memory-resident figure doing "
        "identical work. That gap is the cache, not the pipeline, which is why a ratio taken against it "
        "understates the implementation.",
    ]


def legacy_table(index):
    lines = [
        "| Metric | Value |",
        "| --- | ---: |",
    ]

    for numerator, denominator, label in LEGACY_ROWS:
        lines.append(ratio_row(index, numerator, denominator, label)[0])

    return lines


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

    out = ["### Pipeline efficiency", ""]
    out += efficiency_table(index)[0]
    out += [
        "",
        "The floor is the same reads and the same writes with no crypto at all, so the ratios above are "
        "what encryption and the pipeline's own machinery cost on top of moving the bytes.",
    ]
    out += cross_check(index)

    out += ["", "<details><summary>Where the time goes (one 256 MiB pass)</summary>", ""]
    out += timeline_table(index)
    out += cache_note(index)
    out += ["", "Ratios against cache-resident crypto, kept so older runs stay comparable:", ""]
    out += legacy_table(index)
    out += ["", "</details>", ""]

    out += ["<details><summary>Absolute figures (host dependent, not comparable across runs)</summary>", ""]
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
