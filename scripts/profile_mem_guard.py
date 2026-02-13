import argparse
import cProfile
import os
import pstats
import time

from pangcrypter.utils.mem_guard import (
    _enumerate_reader_pids_windows,
    is_mem_guard_supported,
    PidHandleCache,
    MemGuardScanStats,
)


def run_profile(iterations: int, max_entries: int, cache_cap: int):
    if not is_mem_guard_supported():
        print("Mem guard profiling is supported on Windows only")
        return

    target_pid = os.getpid()
    cursor = 0
    stats = MemGuardScanStats()
    cache = PidHandleCache(cap=cache_cap)

    t0 = time.perf_counter()
    for i in range(iterations):
        s = time.perf_counter()
        owner_map, cursor = _enumerate_reader_pids_windows(
            target_pid,
            start_index=cursor,
            max_entries=max_entries,
            pid_handle_cache=cache,
            stats=stats,
        )
        print(f"scan={i} ms={(time.perf_counter()-s)*1000:.2f} pids={len(owner_map)} cursor={cursor}")
    total_ms = (time.perf_counter() - t0) * 1000.0

    print("\n=== summary ===")
    print(f"iterations={iterations} max_entries={max_entries} cache_cap={cache_cap}")
    print(f"total_ms={total_ms:.2f} avg_ms={total_ms/max(1, iterations):.2f}")
    print(
        f"open_calls={stats.openprocess_calls} open_ok={stats.openprocess_success} "
        f"open_fail={stats.openprocess_fail}"
    )
    print(f"cache_hits={stats.cache_hits} cache_misses={stats.cache_misses} peak_cache={stats.peak_cache_size}")


def main():
    parser = argparse.ArgumentParser(description="Profile mem_guard scanner")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--max-entries", type=int, default=1200)
    parser.add_argument("--cache-cap", type=int, default=128)
    parser.add_argument("--cprofile-out", type=str, default="mem_guard_profile.prof")
    args = parser.parse_args()

    profiler = cProfile.Profile()
    profiler.enable()
    run_profile(args.iterations, args.max_entries, args.cache_cap)
    profiler.disable()
    profiler.dump_stats(args.cprofile_out)

    print(f"\nWrote cProfile stats to: {args.cprofile_out}")
    pstats.Stats(args.cprofile_out).sort_stats("cumtime").print_stats(20)


if __name__ == "__main__":
    main()
