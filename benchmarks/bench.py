#!/usr/bin/env python3
"""
bench.py — measure simple_mhl seal/verify throughput on realistic media workloads.

WHAT THIS DOES
==============
Builds a synthetic test tree on disk that mirrors the file-size shape of real
camera offloads (XAVC .MXF and Apple ProRes 422 HQ .MOV, 4K), then times
seal() and verify() against each roll independently — exactly how MHLs are
created in production (one MHL per camera roll / "root source").

PROFILES
========
The size distribution is calibrated against real DIT reports:

  interviews    ~2.0 TB total across ~14 rolls
                Heavy multi-cam day. Sony FX9V XAVC .MXF on C001-C004 and
                E001-E003 chambers, plus DJI ProRes 422 HQ .MOV on F001-F003
                with monster 100-450 GB drone clips.

  actuality     ~1.15 TB total across ~10 rolls
                Lighter day. Sony FX9V on C001-C003, DJI ProRes on D001-D006.
                Files cap at ~74 GB.

  small         ~5 GB across 3 rolls — quick CI / smoke test.

Each roll is its own directory with its own MHL. The bench seals and verifies
each roll in turn, then reports per-roll timings and a day total.

USAGE
=====
  # Quick smoke test
  uv run benchmarks/bench.py --profile small

  # Realistic actuality-day simulation on production volume
  uv run benchmarks/bench.py --profile actuality --target /Volumes/RAID/bench

  # Heavy interviews day, just xxhash, 2 runs per roll
  uv run benchmarks/bench.py --profile interviews --algos xxhash --runs 2

  # Bench only specific rolls (comma-separated, matched by prefix)
  uv run benchmarks/bench.py --profile interviews --only C001,F003

  # Don't delete the tree on exit
  uv run benchmarks/bench.py --profile actuality --keep

CAVEATS
=======
- Generating 2 TB of /dev/urandom data takes 20-40 minutes on fast NVMe.
- Throughput numbers reflect YOUR storage, not absolute ceiling.
- Cache warming is skipped automatically when a roll exceeds ½ system RAM.
- xxhash on big files is almost always I/O-bound — the number you measure
  IS your storage's read bandwidth ceiling.
"""

import argparse
import os
import shutil
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate simple_mhl.py
# ---------------------------------------------------------------------------

try:
    from mhl_suite import simple_mhl
except ImportError as e:
    sys.stderr.write(f"ERROR: {e}\n")
    sys.stderr.write(
        "Ensure you are running with `uv run benchmarks/bench.py` or that "
        "the package is installed in editable mode.\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Workload model — one Roll per camera/audio source, matching DIT reports
# ---------------------------------------------------------------------------
#
# A "Roll" (called "root source" in ShotPutPro reports) is one camera magazine,
# audio recorder, or stills card. Each roll gets its own MHL file in production.
# A roll contains:
#   - subpath: where its clips live within the roll (e.g. "XDROOT/Clip" for
#     Sony XAVC, "A005_2U3410" for DJI ProRes)
#   - clips: list of (count, mean_size_bytes) tuples describing the clip
#     size distribution within this roll
#
# We bench each roll independently, sealing and verifying it on its own —
# this matches real workflow (one MHL per roll) and gives per-roll timings
# rather than one aggregate number that hides which rolls were slow.

@dataclass
class Roll:
    """One camera/audio/stills roll — one MHL target."""
    name: str                          # e.g. "C001", "F003", "XA001"
    subpath: str                       # within-roll clip folder
    clips: list[tuple[int, int]]       # list of (count, mean_size_bytes)
    extension: str = ".dat"            # cosmetic only

    @property
    def estimated_bytes(self) -> int:
        return sum(count * size for count, size in self.clips)


# Convenient size constants
KB = 1024
MB = 1024 * KB
GB = 1024 * MB

# ---------------------------------------------------------------------------
# Profile: interviews (~2 TB, multi-cam, drone-heavy)
# ---------------------------------------------------------------------------
# Mirrors a real interviews-day shape: Sony FX9V on multiple chambers/cameras
# (XAVC .MXF, /XDROOT/Clip layout) plus DJI drones (Apple ProRes 422 HQ .MOV,
# /F00N_13F36N layout). Drones contribute most of the bytes via a few very
# large clips (100-450 GB each). Audio rolls (XA/XW) are present but empty
# in the source reports — included here as zero-byte placeholders only if
# you want to exercise empty-roll handling; we omit them for the bench.

PROFILE_INTERVIEWS = [
    # Sony FX9V main cameras — XAVC h264 .MXF
    Roll("C001", "XDROOT/Clip", [
        (5, 90 * GB),     # long takes
        (4, 10 * GB),     # mid-length
        (10, 1 * GB),     # short clips
        (5, 500 * MB),    # very short
    ]),
    Roll("C002", "XDROOT/Clip", [
        (3, 60 * GB),
        (4, 30 * GB),
        (8, 3 * GB),
    ]),
    Roll("C003", "XDROOT/Clip", [
        (3, 75 * GB),
        (3, 25 * GB),
        (2, 2 * GB),
    ]),
    Roll("C004", "XDROOT/Clip", [
        (2, 12 * GB),
        (3, 8 * GB),
        (6, 1 * GB),
        (3, 500 * MB),
    ]),
    # Chambers — heavier MXF clips
    Roll("E001", "XDROOT/Clip", [
        (1, 110 * GB),    # one massive 58-min clip
    ]),
    Roll("E002", "XDROOT/Clip", [
        (1, 84 * GB),
        (1, 33 * GB),
    ]),
    Roll("E003", "XDROOT/Clip", [
        (1, 107 * GB),
        (2, 4 * GB),
    ]),
    # DJI drones — Apple ProRes 422 HQ .MOV (the heavy hitters)
    Roll("F001", "F001_13F362", [
        (1, 194 * GB),
        (1, 133 * GB),
        (3, 40 * GB),
        (5, 5 * GB),
        (4, 2 * GB),
    ]),
    Roll("F002", "F001_13F362", [
        (1, 40 * GB),
        (3, 10 * GB),
        (5, 2 * GB),
    ]),
    Roll("F003", "F003_13F361", [
        (1, 448 * GB),     # the monster ProRes drone clip
        (1, 268 * GB),
        (1, 7 * GB),
        (3, 200 * MB),
    ]),
]

# ---------------------------------------------------------------------------
# Profile: actuality (~1.15 TB, location/run-and-gun)
# ---------------------------------------------------------------------------
# Mirrors an actuality-day shape: Sony FX9V on C001-C003 plus DJI drones on
# D001-D006 with smaller per-file ceilings (74 GB max vs 448 GB). More files
# overall in the camera bucket because shoots like this have many short takes.

PROFILE_ACTUALITY = [
    # Sony FX9V — XAVC .MXF
    Roll("C001", "XDROOT/Clip", [
        (3, 18 * GB),
        (4, 9 * GB),
        (8, 3 * GB),
        (10, 1 * GB),
    ]),
    Roll("C002", "XDROOT/Clip", [
        (4, 16 * GB),
        (3, 6 * GB),
    ]),
    Roll("C003", "XDROOT/Clip", [
        (2, 27 * GB),
        (3, 17 * GB),
        (15, 2 * GB),
        (10, 800 * MB),
    ]),
    # DJI drones — Apple ProRes 422 HQ .MOV
    Roll("D001", "A005_2U3410", [
        (1, 58 * GB),
        (2, 30 * GB),
        (5, 5 * GB),
        (10, 3 * GB),
    ]),
    Roll("D002", "A006_2U3411", [
        (1, 65 * GB),
        (1, 46 * GB),
        (3, 22 * GB),
        (10, 5 * GB),
        (4, 2 * GB),
    ]),
    Roll("D003", "A007_2U3412", [
        (1, 64 * GB),
        (1, 34 * GB),
        (3, 2 * GB),
    ]),
    Roll("D004", "A008_2U3413", [
        (3, 7 * GB),
        (5, 4 * GB),
        (5, 2 * GB),
    ]),
    Roll("D005", "A009_2U3414", [
        (5, 3 * GB),
        (2, 2 * GB),
    ]),
    Roll("D006", "A010_2U3415", [
        (1, 74 * GB),
        (5, 8 * GB),
        (10, 5 * GB),
        (8, 2 * GB),
    ]),
]

# ---------------------------------------------------------------------------
# Profile: small (~1 GiB, smoke test)
# ---------------------------------------------------------------------------
PROFILE_SMALL = [
    Roll("C001", "XDROOT/Clip", [
        (2, 200 * MB),
        (3, 50 * MB),
    ]),
    Roll("D001", "A005_2U3410", [
        (2, 100 * MB),
        (4, 30 * MB),
    ]),
    Roll("F001", "F001_13F362", [
        (1, 200 * MB),
        (3, 20 * MB),
    ]),
]

PROFILES = {
    "interviews": PROFILE_INTERVIEWS,
    "actuality":  PROFILE_ACTUALITY,
    "small":      PROFILE_SMALL,
}


# ---------------------------------------------------------------------------
# Workload generation
# ---------------------------------------------------------------------------

# Per-clip size jitter: each clip is mean_size ± 25%. Avoids a homogeneous
# tree where every clip in a bucket is exactly the same size, which would
# let the kernel readahead / fs allocator optimise unrealistically.
JITTER = 0.25

# Stream-write chunk size for generating files. 16 MiB balances:
#   - Small enough to not pin huge RAM via os.urandom buffers
#   - Large enough to amortise syscall overhead
WRITE_CHUNK = 16 * MB


def generate_roll(roll_root: Path, roll: Roll, rng) -> int:
    """
    Materialise one roll's clip files under roll_root/roll.subpath.
    Returns the actual byte count written (which differs from the estimate
    by the jitter factor).
    """
    clip_dir = roll_root / roll.subpath
    clip_dir.mkdir(parents=True, exist_ok=True)

    actual = 0
    clip_idx = 0
    for count, mean_size in roll.clips:
        for _ in range(count):
            jitter = 1.0 + (rng.random() * 2 - 1) * JITTER
            size = max(1, int(mean_size * jitter))

            # Camera-style filename: underscores + hex token to mimic real
            # XAVC/ProRes naming. Exercises any unusual-filename code paths
            # in simple_mhl that wouldn't fire on plain "test_001.dat".
            fname = f"{roll.name}C{clip_idx:04d}_{rng.randint(0, 0xFFFFFF):06X}{roll.extension}"
            path = clip_dir / fname

            with open(path, "wb") as f:
                remaining = size
                while remaining > 0:
                    n = min(remaining, WRITE_CHUNK)
                    f.write(os.urandom(n))
                    remaining -= n
                    actual += n
            clip_idx += 1

    return actual


def warm_roll_cache(roll_root: Path, max_bytes: int) -> bool:
    """
    Read every file in a roll once to populate the OS page cache.
    Skipped if the roll exceeds max_bytes (cache would self-evict).
    Returns True if fully warmed, False if skipped.
    """
    if max_bytes <= 0:
        return False
    total = 0
    for p in roll_root.rglob("*"):
        if p.is_file():
            with open(p, "rb") as f:
                while True:
                    chunk = f.read(4 * MB)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        return False
    return True


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def time_seal(roll_root: Path, algo: str, runs: int) -> list[float]:
    """Run simple_mhl.seal() N times against the roll, return timings (s)."""
    times = []
    for _ in range(runs):
        # Each run starts clean — no leftover .mhl from a prior pass.
        for mhl in roll_root.glob("*.mhl"):
            mhl.unlink()
        t0 = time.perf_counter()
        try:
            simple_mhl.seal(str(roll_root), algo, False)
        except SystemExit as e:
            if e.code not in (0, None):
                sys.stderr.write(f"seal exited {e.code}\n")
        times.append(time.perf_counter() - t0)
    return times


def time_verify(mhl_path: Path, runs: int) -> list[float]:
    """Run simple_mhl.verify() N times against the roll's manifest."""
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            simple_mhl.verify(str(mhl_path))
        except SystemExit as e:
            if e.code not in (0, None):
                sys.stderr.write(f"verify exited {e.code}\n")
        times.append(time.perf_counter() - t0)
    return times


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def fmt_throughput(bytes_processed: int, times: list[float]) -> tuple[str, float]:
    """Format mean/best as MB/s; return (display_string, mean_mbs)."""
    mean = statistics.mean(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0.0
    best = min(times)
    mean_mbs = (bytes_processed / mean) / MB
    best_mbs = (bytes_processed / best) / MB
    stdev_pct = (stdev / mean * 100) if mean else 0
    s = (
        f"mean={mean_mbs:7.1f} MB/s  "
        f"best={best_mbs:7.1f} MB/s  "
        f"stdev={stdev_pct:4.1f}%  "
        f"({mean:.1f}s mean)"
    )
    return s, mean_mbs


def fmt_size(bytes_n: int) -> str:
    """Human-readable size, GiB/TiB."""
    if bytes_n >= 1024**4:
        return f"{bytes_n / 1024**4:.2f} TiB"
    if bytes_n >= 1024**3:
        return f"{bytes_n / 1024**3:.1f} GiB"
    return f"{bytes_n / 1024**2:.0f} MiB"


def fmt_duration(seconds: float) -> str:
    """Render seconds as a human-readable Hh Mm Ss."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--profile", choices=list(PROFILES.keys()), default="small",
        help="Workload shape preset (default: small).",
    )
    parser.add_argument(
        "--target", type=Path, default=None,
        help="Directory to create the test tree in (default: $TMPDIR).",
    )
    parser.add_argument(
        "--algos", nargs="+",
        default=["xxhash"],
        choices=["md5", "sha1", "xxhash"],
        help="Hash algorithms to benchmark (default: xxhash only).",
    )
    parser.add_argument(
        "--runs", type=int, default=2,
        help="Runs per roll per algorithm (default: 2).",
    )
    parser.add_argument(
        "--only", type=str, default=None,
        help=(
            "Comma-separated roll-name prefixes to bench. "
            "E.g. --only C001,F003 benches only those rolls."
        ),
    )
    parser.add_argument(
        "--no-warm", action="store_true",
        help="Skip cache warming even when a roll fits in RAM.",
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="Don't delete the test tree on exit.",
    )
    args = parser.parse_args()

    profile = PROFILES[args.profile]

    # Filter rolls if --only was given
    if args.only:
        wanted = set(args.only.split(","))
        rolls_to_run = [r for r in profile if any(r.name.startswith(w) for w in wanted)]
        if not rolls_to_run:
            sys.stderr.write(f"No rolls match --only={args.only}\n")
            return 1
    else:
        rolls_to_run = list(profile)

    estimated_bytes = sum(r.estimated_bytes for r in rolls_to_run)
    print(f"Profile: {args.profile}")
    print(f"Rolls:   {len(rolls_to_run)} ({', '.join(r.name for r in rolls_to_run)})")
    print(f"Total:   {fmt_size(estimated_bytes)}")
    print()

    if estimated_bytes > 500 * GB:
        gen_seconds = estimated_bytes / (500 * MB)  # ~500 MB/s gen on fast NVMe
        print(f"⚠ Generation alone may take ~{fmt_duration(gen_seconds)} on fast NVMe.")
        print()

    # --- Set up the workload --------------------------------------------------
    if args.target:
        args.target.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="mhl_bench_", dir=str(args.target)))
    else:
        tmp = Path(tempfile.mkdtemp(prefix="mhl_bench_"))

    # Determine RAM budget for cache warming once, up front
    try:
        import psutil
        half_ram = psutil.virtual_memory().total // 2
    except ImportError:
        half_ram = 32 * GB  # fallback assumption

    try:
        # Deterministic jitter seed across the whole bench so re-runs match.
        # Per-clip data still uses os.urandom — that's the actual random part.
        import random
        rng = random.Random(0x5EA1ED)

        # --- Generate all rolls up front -------------------------------------
        # We generate the whole tree before timing anything so that bench
        # timings aren't affected by partial-cache state from generation.
        print("Generating rolls ...")
        roll_dirs: dict[str, Path] = {}
        roll_actuals: dict[str, int] = {}
        gen_start = time.perf_counter()
        for roll in rolls_to_run:
            roll_dir = tmp / roll.name
            t0 = time.perf_counter()
            actual = generate_roll(roll_dir, roll, rng)
            roll_dirs[roll.name] = roll_dir
            roll_actuals[roll.name] = actual
            elapsed = time.perf_counter() - t0
            mbs = (actual / elapsed) / MB if elapsed > 0 else 0
            print(
                f"  {roll.name:<6s}  {fmt_size(actual):>10s}  "
                f"in {fmt_duration(elapsed):>8s}  ({mbs:.0f} MB/s gen)"
            )
        total_actual = sum(roll_actuals.values())
        print(
            f"  Total:   {fmt_size(total_actual)} in "
            f"{fmt_duration(time.perf_counter() - gen_start)}"
        )
        print()

        # --- Bench each roll, each algo --------------------------------------
        # Per-roll results: rolls[roll_name][algo] = {seal_mbs, verify_mbs, seal_s, verify_s}
        results: dict[str, dict[str, dict[str, float]]] = {}

        for algo in args.algos:
            print(f"=== {algo} ===")
            print(
                f"  {'roll':<6s}  {'size':>10s}  "
                f"{'seal':<42s}  {'verify':<42s}"
            )
            algo_seal_total = 0.0
            algo_verify_total = 0.0

            for roll in rolls_to_run:
                roll_dir = roll_dirs[roll.name]
                actual = roll_actuals[roll.name]

                # Cache warming decision per-roll: warm if it fits in ½ RAM.
                if args.no_warm:
                    pass
                elif actual > half_ram:
                    pass  # silently skip — total roll-by-roll output is enough
                else:
                    warm_roll_cache(roll_dir, max_bytes=half_ram)

                # Seal
                seal_times = time_seal(roll_dir, algo, runs=args.runs)
                seal_str, seal_mbs = fmt_throughput(actual, seal_times)
                algo_seal_total += statistics.mean(seal_times)

                # Verify (using the manifest the seal just produced)
                mhl = next(roll_dir.glob("*.mhl"))
                verify_times = time_verify(mhl, runs=args.runs)
                verify_str, verify_mbs = fmt_throughput(actual, verify_times)
                algo_verify_total += statistics.mean(verify_times)

                print(
                    f"  {roll.name:<6s}  {fmt_size(actual):>10s}  "
                    f"{seal_str:<42s}  {verify_str:<42s}"
                )

                # Clean .mhl between algos so the next algo starts fresh.
                for m in roll_dir.glob("*.mhl"):
                    m.unlink()

                results.setdefault(roll.name, {})[algo] = {
                    "seal_mbs":   seal_mbs,
                    "verify_mbs": verify_mbs,
                }

            # Day total: aggregate seal/verify time across all rolls
            agg_seal_mbs = (total_actual / algo_seal_total) / MB
            agg_verify_mbs = (total_actual / algo_verify_total) / MB
            print(
                f"  {'TOTAL':<6s}  {fmt_size(total_actual):>10s}  "
                f"seal {fmt_duration(algo_seal_total)} ({agg_seal_mbs:.0f} MB/s agg)   "
                f"verify {fmt_duration(algo_verify_total)} ({agg_verify_mbs:.0f} MB/s agg)"
            )
            print()

        if args.keep:
            print(f"Test tree preserved at: {tmp}")

        return 0
    finally:
        if not args.keep:
            print(f"Cleaning up test tree {tmp} ...")
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
