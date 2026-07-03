# NAS Parallelisation Testing Guide

## Context

The adaptive hashing concurrency system is now live in both seal and verify (`src/mhl_suite/hashing.py`). It automatically measures storage bandwidth and tunes worker count to avoid harming throughput on slow/seek-bound devices. Shipped state:

- **Adaptive controller** (`_hash_jobs_auto`): measures single-stream read bandwidth, compares to in-RAM hash speed, decides parallel-vs-sequential before any hashing happens.
- **Per-window re-measurement**: if a parallel window's throughput < single-core hash speed, demotes to sequential for the remainder (catches warm cache false-positives).
- **Tested on**: fast SSD (ramped to 16 workers, ~2.4× on md5), slow SSD (sequential), 68 MB/s USB HDD (sequential, zero seek-thrashing).
- **No operator knob**: `-j` flag removed; the script alone decides.

## The NAS Gap

A typical NAS (like EditShare Ultimate EFS) has a property our current controller doesn't exploit: **multi-stream aggregate bandwidth >> single-stream**. 

Example: EditShare reads at 100 MB/s single-stream but 800 MB/s with 8 concurrent reads. Our probe measures only single-stream (100 MB/s), compares to md5 speed (~950 MB/s), decides disk-bound → sequential → never parallelises → **leaves 8× throughput on the table.**

The deferred work: a **promotion probe** that detects and exploits this scaling.

## Testing on Your NAS Sandbox

### Phase 1: Characterise the storage (no code change)

**Goal**: understand if EditShare EFS scales with concurrent reads, and by how much.

**Setup**: a cold-read benchmark script (not hashing, just reading) to measure:
- Single-stream buffered read bandwidth
- 2/4/8-stream aggregate buffered read bandwidth
- Whether it scales linearly, sub-linearly, or plateaus

**Methodology**:
```bash
# On the NAS-mounted volume, measure buffered (not F_NOCACHE) cold reads.
# Create a 10 GB test file, unmount and remount to flush cache, then:

# Single-stream
time dd if=testfile of=/dev/null bs=1M

# 2-stream (two processes reading from different offsets)
(dd if=testfile of=/dev/null bs=1M skip=0 &) && (dd if=testfile of=/dev/null bs=1M skip=5120 &) && wait

# 4-stream, 8-stream, etc.
```

Record: throughput (MB/s) vs. stream count. If 8-stream gives 600+ MB/s (6× the 100 MB/s single-stream), you have a scaling NAS.

### Phase 2: Validate current behavior on the NAS

Run the adaptive system as-is and observe:
```bash
# Seal a few GB of media on the NAS (use -v to see timing)
simple-mhl seal /path/on/nas -a md5 -v

# Verify the manifest
simple-mhl verify /path/on/nas/*.mhl -v
```

**Expected**: both will run sequentially (single-stream probe decides sequential), even though parallel would be faster. Time them; they'll be slow.

### Phase 3: Sketch the promotion probe (pre-implementation)

Once you confirm EditShare scales, we design:

1. **Existing probe** (unchanged): measure single-stream read bandwidth.
2. **Promotion probe** (new): try a small concurrent window (e.g., 2–4 streams, read ~256 MB total) and measure aggregate bandwidth.
3. **Decision logic**:
   - If `aggregate_bw > 1.3 × hash_bw`, parallelism likely helps → use `round(aggregate_bw / hash_bw)` workers.
   - If `aggregate_bw ≤ hash_bw`, disk is still the ceiling → stay sequential.
   - Handles both cases: a scaling NAS (aggregate >> single) and a seek-bound single disk (aggregate ≈ single).

4. **Cost**: two probes (~1 GB each) instead of one, buffered cold reads (~1–2 seconds on a fast NAS). Deferred until the NAS sandbox confirms the pattern is worth it.

## What to Report Back

After Phase 1 (characterisation):

- **Single-stream read MB/s** on EditShare
- **2/4/8-stream aggregate read MB/s**
- **Scaling factor** (8-stream ÷ single-stream)
- Any observations about cache behavior, seek patterns, or latency variance across streams

This will tell us whether the promotion probe is worth building. If EditShare doesn't scale with concurrent reads, the current system is already optimal.

## Implementation (when ready)

Changes will be minimal and isolated to `src/mhl_suite/hashing.py`:

1. Add `_probe_read_bw_multi(paths, stream_count)` — measures concurrent read bandwidth.
2. Update `_hash_jobs_auto` to optionally try the promotion probe if single-stream looks slow.
3. Use aggregate bandwidth in the worker formula if it suggests parallelism is worthwhile.
4. Fold in the deferred **probe-skip optimization** (skip probe when hash is known to always out-run disk).

All changes stay within the controller; seal/verify/ascmhl-verify call sites unchanged.
