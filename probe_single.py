"""
Single-site smoke test: igihe.com, Initial_Load, 1 repetition.
Confirms HAR byte enrichment works before running the full experiment.
Run:  python probe_single.py
"""
import asyncio
import json
from collections import Counter
from pathlib import Path

import tracker_measurement as tm
from tracker_measurement import build_tracker_domains, run_single


async def probe() -> None:
    output_dirs = {
        "root":       Path("tracker_results"),
        "hars":       Path("tracker_results/hars"),
        "logs":       Path("tracker_results/logs"),
        "aggregated": Path("tracker_results/aggregated"),
        "blocklists": Path("tracker_results/blocklists"),
    }
    for d in output_dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    # Set up logging so we see INFO output
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Load blocklists
    tm.TRACKER_DOMAINS = build_tracker_domains(
        Path("tracker_results/blocklists/easyprivacy_domains.txt"),
        Path("data/domains/"),
    )

    site = {
        "id": 2,
        "domain": "igihe.com",
        "url": "https://www.igihe.com",
        "category": "News",
    }

    result = await run_single(site, "Initial_Load", 1, output_dirs, timeout_ms=30000)

    print()
    print("=== PROBE RESULT ===")
    print(f"Status       : {result['status']}")
    print(f"Duration     : {result['duration_s']}s")
    total_mb = result["total_bytes"] / (1024 * 1024)
    tracker_mb = result["tracker_bytes"] / (1024 * 1024)
    print(f"Total bytes  : {result['total_bytes']:,}  ({total_mb:.3f} MB)")
    print(f"Tracker bytes: {result['tracker_bytes']:,}  ({tracker_mb:.3f} MB)")
    print(f"Tracker share: {result['tracker_share_pct']}%")
    print(f"Total reqs   : {result['total_requests']}")
    print(f"Tracker reqs : {result['tracker_requests']}")

    # Byte source breakdown from HAR enrichment
    reqs = result["requests_log"]
    sources = Counter(r.get("bytes_source", "unknown") for r in reqs)
    print()
    print("Byte sources (HAR enrichment breakdown):")
    for src, cnt in sorted(sources.items()):
        print(f"  {src:30s}: {cnt:4d} requests")

    # Cached requests count
    cached = sum(1 for r in reqs if r.get("cached", False))
    print(f"  {'cached (transfer_size=-1)':30s}: {cached:4d} requests")

    # Top tracker domains
    trackers = [r for r in reqs if r.get("is_third_party_tracker")]
    top_trackers = Counter(r["domain"] for r in trackers).most_common(10)
    print()
    print("Top tracker domains:")
    for dom, cnt in top_trackers:
        tracker_bytes_for_dom = sum(r["bytes"] for r in trackers if r["domain"] == dom)
        print(f"  {dom:40s}: {cnt:3d} req  {tracker_bytes_for_dom/1024:.1f} KB")

    # Cost estimate preview
    cost_est = tm._compute_cost_estimates(result["tracker_bytes"])
    print()
    print("Cost estimates (tracker traffic):")
    for profile in tm.REPORTING_PROFILES:
        e = cost_est[profile]
        anchor = " [REPORTING ANCHOR]" if e["reporting_anchor"] else ""
        print(f"  {profile:25s}: {e['estimated_cost_rwf']:.6f} RWF  (@{e['rwf_per_mb']} RWF/MB){anchor}")

    print()
    print(f"HAR file     : {result['har_file']}")
    print(f"Summary JSON : tracker_results/logs/igihe_com_Initial_Load_run1_summary.json")
    print()
    print("=== PROBE COMPLETE ===")


if __name__ == "__main__":
    asyncio.run(probe())
