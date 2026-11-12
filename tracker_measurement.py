"""
Playwright Web Tracker & Network Traffic Measurement Script
Project: Paying to Be Watched: How Hidden Trackers Eat Rwandans' Mobile Data
Authors: Swafiyah Wanjiru Gichuki & Ange Kimberly Mukeshimana
"""
# tracker_measurement.py
# Measures network traffic before/after consent on Rwandan websites

import argparse
import asyncio
import csv
import json
import logging
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import tldextract
import urllib.request

from playwright.async_api import async_playwright, Page, Response, BrowserContext

# ---------------------------------------------------------------------------
# Logging — configured after CLI args are parsed so we know the output dir.
# A module-level logger is used throughout; handlers are added in main().
# ---------------------------------------------------------------------------
log = logging.getLogger("tracker")

# ---------------------------------------------------------------------------
# Pricing data — hardcoded as of 11 November 2026
# Sources: mtn.co.rw, airtel.rw, RURA Q1 2026 tariff bulletin
# ---------------------------------------------------------------------------
PRICE_PROFILES: Dict[str, float] = {
    # --- MTN Rwanda ---
    "mtn_daily_1500mb":    0.33,  # 1.5 GB / 24hr / 500 RWF (standard)
    "mtn_segmented_daily": 0.20,  # 1.5 GB / 24hr / 300 RWF (eligibility-dependent)
    "mtn_monthly_30gb":    0.33,  # 30 GB / 30 days / 10,000 RWF

    # --- Airtel Rwanda ---
    "airtel_daily_1gb":    0.20,  # 1 GB / 24hr / 200 RWF
    "airtel_48hr_3500mb":  0.14,  # 3.5 GB / 48hr / 500 RWF
    "airtel_smarta_30gb":  0.10,  # 30 GB (1 GB/day) / 30 days / 3,000 RWF
    "airtel_combo_60gb":   0.08,  # 60 GB (2 GB/day) / 30 days / 5,000 RWF
    "airtel_monthly_30gb": 0.33,  # 30 GB / 30 days / 10,000 RWF

    # --- RURA Regulatory Averages (Q1 2026) ---
    "rura_mtn_inbundle":   0.85,  # RURA Q1 2026 effective average
    "rura_airtel_inbundle": 0.23, # RURA Q1 2026 effective average

    # --- Out-of-bundle (reference only, not used in main cost calc) ---
    "mtn_out_of_bundle":  10.00,  # RURA Q1 2026
    "airtel_out_of_bundle": 5.00, # RURA Q1 2026
}

# Four reporting anchors highlighted in results table
REPORTING_PROFILES: List[str] = [
    "airtel_combo_60gb",   # 0.08 — cheapest accessible option
    "airtel_daily_1gb",    # 0.20 — typical budget daily user
    "mtn_daily_1500mb",    # 0.33 — most common MTN entry point
    "rura_mtn_inbundle",   # 0.85 — official regulatory benchmark
]

# RURA quarterly tariff history
RURA_QUARTERLY_TARIFFS: Dict[str, Any] = {
    "MTN_Rwandacell": {
        "Q2_2025": 0.9702,
        "Q3_2025": 0.9594,
        "Q4_2025": 0.8573,
        "Q1_2026": 0.8463,
        "Q2_2026": 0.9967,
    },
    "Airtel_Rwanda": {
        "Q2_2025": 0.2683,
        "Q3_2025": 0.2475,
        "Q4_2025": 0.2433,
        "Q1_2026": 0.2310,
        "Q2_2026": 0.2310,
    },
    "National_ISP_Average": {
        "Q2_2025": 0.8543,
        "Q3_2025": 0.8328,
        "Q4_2025": 0.7597,
        "Q1_2026": 0.7556,
        "Q2_2026": 0.7894,
    },
}

RURA_OUT_OF_BUNDLE: Dict[str, float] = {
    "MTN_Rwandacell": 10.00,
    "Airtel_Rwanda":   5.00,
}

# Q1 2026 is the primary reference quarter (most recent complete figure).
# Logged in every aggregated summary so the choice is always traceable.
RURA_REFERENCE_QUARTER: str = "Q1_2026"

# ---------------------------------------------------------------------------
# Blocklist loading — Task 1
# ---------------------------------------------------------------------------
# Primary URL plus two fallback mirrors (tried in order on any failure/403).
EASYPRIVACY_URLS = [
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy.txt",
    "https://filters.adtidy.org/extension/ublock/filters/118_optimized.txt",
]
EASYPRIVACY_MAX_AGE_DAYS = 7


def _load_easyprivacy(cache_path: Path) -> Set[str]:
    """Fetch EasyPrivacy (with mirror fallbacks), cache to disk, re-use if fresh (< 7 days old)."""
    domains: Set[str] = set()

    need_fetch = True
    if cache_path.exists():
        age_days = (time.time() - cache_path.stat().st_mtime) / 86400
        if age_days < EASYPRIVACY_MAX_AGE_DAYS:
            need_fetch = False
            log.info(f"EasyPrivacy cache is {age_days:.1f} days old — using cached copy")

    if need_fetch:
        fetched = False
        for url in EASYPRIVACY_URLS:
            log.info(f"Fetching EasyPrivacy from {url} …")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(text, encoding="utf-8")
                log.info(f"EasyPrivacy downloaded from {url} and cached.")
                fetched = True
                break
            except Exception as exc:
                log.warning(f"EasyPrivacy fetch failed ({url}): {exc} — trying next mirror")

        if not fetched:
            if cache_path.exists():
                log.warning("All EasyPrivacy mirrors failed — falling back to stale cache.")
            else:
                log.warning("All EasyPrivacy mirrors failed and no cache available — skipping.")
                return domains

    raw = cache_path.read_text(encoding="utf-8", errors="replace")
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("||") and line.endswith("^"):
            domain = line[2:-1].split("/")[0].split("^")[0]
            if domain:
                domains.add(domain.lower())

    log.info(f"EasyPrivacy: loaded {len(domains):,} domain rules")
    return domains


def _load_tracker_radar(radar_dir: Path) -> Set[str]:
    """
    Load DuckDuckGo Tracker Radar domains from the domains/ folder.

    Each file is named <domain>.json (e.g. 'googletagmanager.com.json').
    The stem of the filename IS the tracker domain — no JSON parsing required.
    This is orders of magnitude faster than reading every file's content.
    Files with URL-encoded characters (e.g. '%2a.googleapis.com.json') are
    decoded so the domain is stored in plain form.
    """
    from urllib.parse import unquote
    domains: Set[str] = set()
    count = 0
    for json_file in radar_dir.rglob("*.json"):
        stem = unquote(json_file.stem).lower()
        # Skip placeholder/invalid names
        if "." in stem and not stem.startswith("."):
            domains.add(stem)
        count += 1
    log.info(f"Tracker Radar: loaded {len(domains):,} domains from {count:,} files")
    return domains


def build_tracker_domains(easyprivacy_cache: Path, radar_dir: Path) -> Set[str]:
    """Merge EasyPrivacy and DuckDuckGo Tracker Radar into one set."""
    ep_domains = _load_easyprivacy(easyprivacy_cache)
    tr_domains = _load_tracker_radar(radar_dir)
    merged = ep_domains | tr_domains
    log.info(
        f"TRACKER_DOMAINS merged: {len(merged):,} total "
        f"(EasyPrivacy={len(ep_domains):,}, TrackerRadar={len(tr_domains):,})"
    )
    return merged


# Will be populated at startup in main()
TRACKER_DOMAINS: Set[str] = set()

# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def extract_etld_plus_one(url: str) -> str:
    """Return the eTLD+1 of a URL (e.g. 'google.com' for 'fonts.google.com')."""
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        # Fallback for bare IPs or unusual URLs
        hostname = urlparse(url).hostname
        if not hostname:
            return ""
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return hostname.lower()
    except Exception:
        return ""


def is_third_party_tracker(request_url: str, page_domain: str) -> bool:
    """Return True if the request domain is a known tracker and is third-party."""
    req_domain = extract_etld_plus_one(request_url)
    if not req_domain or req_domain == page_domain:
        return False
    req_hostname = urlparse(request_url).hostname or ""
    req_hostname = req_hostname.lower()

    for tracker in TRACKER_DOMAINS:
        if req_domain == tracker or req_hostname == tracker or req_hostname.endswith(f".{tracker}"):
            return True
    return False


# ---------------------------------------------------------------------------
# Consent banner handler — Task (already written, kept intact)
# ---------------------------------------------------------------------------

async def handle_consent_banner(page: Page, action: str) -> bool:
    """
    Handles cookie banners for Condition 2 (Reject) and Condition 3 (Accept).
    Attempts common DOM selectors for CMP banners (OneTrust, Cookiebot, etc.).
    Uses locator().wait_for() instead of is_visible() so the timeout parameter
    is supported correctly by Playwright's API.
    """
    try:
        if action == "reject":
            selectors = [
                "button:has-text('Reject All')",
                "button:has-text('Decline')",
                "button:has-text('Only Essential')",
                "#onetrust-reject-all-handler",
            ]
        elif action == "accept":
            selectors = [
                "button:has-text('Accept All')",
                "button:has-text('Agree')",
                "button:has-text('Allow')",
                "#onetrust-accept-btn-handler",
            ]
        else:
            return False

        for selector in selectors:
            try:
                await page.locator(selector).wait_for(state="visible", timeout=2000)
                await page.locator(selector).click()
                log.info(f"Triggered consent {action.upper()} via selector: {selector}")
                return True
            except Exception:
                continue

    except Exception as e:
        log.debug(f"Consent handler ({action}) error: {e}")

    return False


# ---------------------------------------------------------------------------
# HAR byte extraction — Task 2
# ---------------------------------------------------------------------------

def _enrich_from_har(network_requests: List[Dict[str, Any]], har_path: Path) -> None:
    """
    Re-parse the saved HAR file and apply _transferSize as the primary byte measure.

    Rules per spec:
      _transferSize > 0  → bytes_transferred = _transferSize
      _transferSize == -1 → bytes_transferred = 0, cached = True
      _transferSize missing → bytes_transferred = bytes_header (fallback), bytes_source = "header_fallback"
    """
    if not har_path.exists():
        log.warning(f"HAR file not found for enrichment: {har_path}")
        return

    try:
        har_data = json.loads(har_path.read_bytes())
    except Exception as exc:
        log.warning(f"Could not parse HAR file {har_path}: {exc}")
        return

    entries = har_data.get("log", {}).get("entries", [])

    # Build a URL → list[entry] map (a URL can appear multiple times)
    from collections import defaultdict
    har_by_url: Dict[str, List[Dict]] = defaultdict(list)
    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        har_by_url[url].append(entry)

    # Track how many of each URL we've consumed to handle duplicates
    consumed: Dict[str, int] = defaultdict(int)

    for rec in network_requests:
        url = rec.get("url", "")
        idx = consumed[url]
        matching = har_by_url.get(url, [])

        if idx < len(matching):
            entry = matching[idx]
            consumed[url] += 1
        else:
            # URL not in HAR — keep header fallback
            rec.setdefault("bytes_source", "header_fallback")
            continue

        # Keep the original header value for comparison
        rec["bytes_header"] = rec.get("bytes", 0)

        # Playwright writes _transferSize under entry.response._transferSize;
        # the HAR spec places it at the entry level — check both.
        response_obj = entry.get("response", {})
        transfer_size = entry.get("_transferSize", response_obj.get("_transferSize"))

        # If _transferSize is absent, fall back to HAR bodySize, then content.size
        if transfer_size is None:
            body_size = response_obj.get("bodySize")
            content_size = response_obj.get("content", {}).get("size")
            if body_size is not None and body_size >= 0:
                transfer_size = body_size
            elif content_size is not None and content_size >= 0:
                transfer_size = content_size

        if transfer_size is None:
            rec["bytes_transferred"] = rec["bytes_header"]
            rec["bytes_source"] = "header_fallback"
        elif transfer_size == -1:
            rec["bytes_transferred"] = 0
            rec["cached"] = True
            rec["bytes_source"] = "har_cached"
        else:
            rec["bytes_transferred"] = max(0, transfer_size)
            rec["bytes_source"] = "har_transfer_size"

        # Update the primary "bytes" field to the HAR-derived value
        rec["bytes"] = rec["bytes_transferred"]


# ---------------------------------------------------------------------------
# Single-run measurement — Tasks 2, 3, 4
# ---------------------------------------------------------------------------

MOBILE_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 11; Infinix X688B) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/114.0.0.0 Mobile Safari/537.36"
)


async def run_single(
    site: Dict[str, Any],
    condition: str,
    run_number: int,
    output_dirs: Dict[str, Path],
    timeout_ms: int = 30000,
) -> Dict[str, Any]:
    """
    Execute one browser session for a given site / condition / repetition.
    Returns a summary dict; always returns (never raises) — failures are recorded.
    """
    url = site["url"]
    site_id = site["id"]
    domain = site["domain"]
    page_domain = extract_etld_plus_one(url)
    sanitized = domain.replace(".", "_")

    har_path = output_dirs["hars"] / f"{sanitized}_{condition}_run{run_number}.har"
    summary_path = output_dirs["logs"] / f"{sanitized}_{condition}_run{run_number}_summary.json"

    network_requests: List[Dict[str, Any]] = []
    pre_reload = True
    banner_found = False
    banner_interacted = False
    nav_status = "UNKNOWN"
    t_start = time.monotonic()
    error_msg: Optional[str] = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            # Task 4: Mobile device emulation
            context: BrowserContext = await browser.new_context(
                viewport={"width": 360, "height": 640},
                user_agent=MOBILE_USER_AGENT,
                record_har_path=str(har_path),
            )
            page = await context.new_page()

            async def on_response(res: Response) -> None:
                try:
                    req = res.request
                    content_length = 0
                    cl_header = res.headers.get("content-length", "")
                    if cl_header.strip().isdigit():
                        content_length = int(cl_header.strip())
                    network_requests.append({
                        "url": req.url,
                        "domain": extract_etld_plus_one(req.url),
                        "resource_type": req.resource_type,
                        "status": res.status,
                        "bytes": content_length,
                        "bytes_header": content_length,
                        "bytes_source": "header",
                        "is_third_party_tracker": is_third_party_tracker(req.url, page_domain),
                        "pre_reload": pre_reload,
                        "cached": False,
                    })
                except Exception as exc:
                    log.debug(f"Error logging response: {exc}")

            page.on("response", on_response)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                nav_status = "SUCCESS_DOMCONTENTLOADED"

                if condition in ("Rejected", "Accepted"):
                    action = "reject" if condition == "Rejected" else "accept"
                    banner_found = True  # we attempt; set True optimistically
                    interacted = await handle_consent_banner(page, action=action)
                    banner_interacted = interacted
                    if not interacted:
                        banner_found = False  # no selector matched
                    if interacted:
                        await asyncio.sleep(3)
                        pre_reload = False
                        await page.reload(wait_until="domcontentloaded", timeout=timeout_ms)

                # Non-blocking networkidle wait (capped at 10 s)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                    nav_status = "SUCCESS_NETWORKIDLE"
                except Exception:
                    pass

                # 5-second settling window for delayed tracker injections
                await asyncio.sleep(5)

            except Exception as err:
                error_msg = str(err)
                nav_status = "FAILED"
                log.error(f"Navigation error on {url} [{condition} run={run_number}]: {err}")

            await context.close()
            await browser.close()

    except Exception as outer_err:
        error_msg = str(outer_err)
        nav_status = "FAILED"
        log.error(f"Browser launch error on {url} [{condition} run={run_number}]: {outer_err}")

    duration = time.monotonic() - t_start

    # Task 2: Re-enrich bytes from HAR _transferSize
    _enrich_from_har(network_requests, har_path)

    # Compute metrics using HAR-derived bytes
    total_bytes = sum(r["bytes"] for r in network_requests)
    tracker_requests = [r for r in network_requests if r["is_third_party_tracker"]]
    tracker_bytes = sum(r["bytes"] for r in tracker_requests)
    tracker_share_pct = (tracker_bytes / total_bytes * 100) if total_bytes > 0 else 0.0

    # Post-reload figures (only meaningful for Conditions 2 & 3)
    post_requests = [r for r in network_requests if not r["pre_reload"]]
    post_tracker_bytes = sum(r["bytes"] for r in post_requests if r["is_third_party_tracker"])
    post_total_bytes = sum(r["bytes"] for r in post_requests)
    post_tracker_share_pct = (
        (post_tracker_bytes / post_total_bytes * 100) if post_total_bytes > 0 else 0.0
    )

    summary: Dict[str, Any] = {
        "site_id": site_id,
        "domain": domain,
        "category": site.get("category", ""),
        "target_url": url,
        "page_domain": page_domain,
        "condition": condition,
        "run_number": run_number,
        "status": nav_status,
        "duration_s": round(duration, 2),
        "banner_found": banner_found,
        "banner_interacted": banner_interacted,
        "total_requests": len(network_requests),
        "total_bytes": total_bytes,
        "tracker_requests": len(tracker_requests),
        "tracker_bytes": tracker_bytes,
        "tracker_share_pct": round(tracker_share_pct, 2),
        "post_reload_total_bytes": post_total_bytes,
        "post_reload_tracker_bytes": post_tracker_bytes,
        "post_reload_tracker_share_pct": round(post_tracker_share_pct, 2),
        "har_file": str(har_path),
        "requests_log": network_requests,
    }
    if error_msg:
        summary["error"] = error_msg

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# Aggregation helpers — Task 3 & 5
# ---------------------------------------------------------------------------

def _safe_stdev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def _compute_cost_estimates(tracker_bytes: float) -> Dict[str, Any]:
    """Task 5: Compute RWF cost of tracker traffic across all price profiles."""
    tracker_mb = tracker_bytes / (1024 * 1024)
    estimates: Dict[str, Any] = {}
    for profile, rwf_per_mb in PRICE_PROFILES.items():
        estimates[profile] = {
            "rwf_per_mb": rwf_per_mb,
            "estimated_cost_rwf": round(tracker_mb * rwf_per_mb, 6),
            "reporting_anchor": profile in REPORTING_PROFILES,
        }
    return estimates


def aggregate_condition_runs(
    runs: List[Dict[str, Any]],
    site: Dict[str, Any],
    condition: str,
) -> Dict[str, Any]:
    """Aggregate 3 repetitions of a single condition into mean/stdev metrics."""
    successful = [r for r in runs if r.get("status", "").startswith("SUCCESS")]
    failed_count = len(runs) - len(successful)

    total_bytes_vals = [r["total_bytes"] for r in successful]
    tracker_bytes_vals = [r["tracker_bytes"] for r in successful]
    tracker_share_vals = [r["tracker_share_pct"] for r in successful]
    post_tracker_share_vals = [r["post_reload_tracker_share_pct"] for r in successful]

    mean_total_bytes = statistics.mean(total_bytes_vals) if total_bytes_vals else 0.0
    mean_tracker_bytes = statistics.mean(tracker_bytes_vals) if tracker_bytes_vals else 0.0
    mean_tracker_share = statistics.mean(tracker_share_vals) if tracker_share_vals else 0.0
    stdev_tracker_share = _safe_stdev(tracker_share_vals)
    mean_post_tracker_share = statistics.mean(post_tracker_share_vals) if post_tracker_share_vals else 0.0

    banner_found = any(r.get("banner_found", False) for r in runs)
    banner_interacted = any(r.get("banner_interacted", False) for r in runs)

    agg: Dict[str, Any] = {
        "site_id": site["id"],
        "domain": site["domain"],
        "category": site.get("category", ""),
        "target_url": site["url"],
        "condition": condition,
        "runs_completed": len(successful),
        "runs_failed": failed_count,
        "total_bytes_mean": round(mean_total_bytes, 2),
        "tracker_bytes_mean": round(mean_tracker_bytes, 2),
        "tracker_share_pct_mean": round(mean_tracker_share, 4),
        "tracker_share_pct_stdev": round(stdev_tracker_share, 4),
        "post_reload_tracker_share_pct_mean": round(mean_post_tracker_share, 4),
        "banner_found": banner_found,
        "banner_interacted": banner_interacted,
        "cost_estimates": _compute_cost_estimates(mean_tracker_bytes),
        "rura_reference_quarter": RURA_REFERENCE_QUARTER,
        "rura_quarterly_tariffs": RURA_QUARTERLY_TARIFFS,
        "run_summaries": [
            {
                "run_number": r["run_number"],
                "status": r.get("status"),
                "total_bytes": r.get("total_bytes", 0),
                "tracker_bytes": r.get("tracker_bytes", 0),
                "tracker_share_pct": r.get("tracker_share_pct", 0.0),
                "duration_s": r.get("duration_s", 0.0),
            }
            for r in runs
        ],
    }
    return agg


def aggregate_site_conditions(
    condition_aggs: Dict[str, Dict[str, Any]],
    site: Dict[str, Any],
) -> Dict[str, Any]:
    """Produce a final per-site aggregated JSON across all three conditions."""
    all_tracker_bytes = [
        v["tracker_bytes_mean"]
        for v in condition_aggs.values()
        if v["runs_completed"] > 0
    ]
    all_total_bytes = [
        v["total_bytes_mean"]
        for v in condition_aggs.values()
        if v["runs_completed"] > 0
    ]

    overall_tracker_bytes = statistics.mean(all_tracker_bytes) if all_tracker_bytes else 0.0
    overall_total_bytes = statistics.mean(all_total_bytes) if all_total_bytes else 0.0
    overall_tracker_share = (
        (overall_tracker_bytes / overall_total_bytes * 100) if overall_total_bytes > 0 else 0.0
    )

    return {
        "site_id": site["id"],
        "domain": site["domain"],
        "category": site.get("category", ""),
        "target_url": site["url"],
        "overall_tracker_bytes_mean": round(overall_tracker_bytes, 2),
        "overall_total_bytes_mean": round(overall_total_bytes, 2),
        "overall_tracker_share_pct": round(overall_tracker_share, 4),
        "cost_estimates": _compute_cost_estimates(overall_tracker_bytes),
        "conditions": condition_aggs,
        "rura_reference_quarter": RURA_REFERENCE_QUARTER,
        "rura_quarterly_tariffs": RURA_QUARTERLY_TARIFFS,
    }


# ---------------------------------------------------------------------------
# Run log writer — Task 7
# ---------------------------------------------------------------------------

def _write_run_log(
    run_log_path: Path,
    site: Dict[str, Any],
    condition: str,
    run_number: int,
    result: Dict[str, Any],
) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    domain = site["domain"]
    status = result.get("status", "FAILED")
    duration = result.get("duration_s", 0.0)
    banner_found = str(result.get("banner_found", False)).lower()
    tracker_share = result.get("tracker_share_pct", 0.0)
    error = result.get("error", "")

    if status.startswith("SUCCESS"):
        interacted = str(result.get("banner_interacted", False)).lower()
        line = (
            f"[{ts}] site={domain} condition={condition} run={run_number} "
            f"status={status} duration={duration}s "
            f"banner_found={banner_found} interacted={interacted} "
            f"tracker_share={tracker_share}%\n"
        )
    else:
        line = (
            f"[{ts}] site={domain} condition={condition} run={run_number} "
            f"status=FAILED error={error!r}\n"
        )

    with open(run_log_path, "a", encoding="utf-8") as f:
        f.write(line)


# ---------------------------------------------------------------------------
# CSV export — Task 6
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "site_id", "domain", "category", "condition",
    "total_bytes_mb", "tracker_bytes_mb", "tracker_share_pct",
    "tracker_share_pct_stdev", "runs_completed", "runs_failed",
    "cost_airtel_combo_60gb", "cost_airtel_daily_1gb",
    "cost_mtn_daily_1500mb", "cost_rura_mtn_inbundle",
    "cost_mtn_out_of_bundle", "cost_airtel_out_of_bundle",
    "banner_found", "banner_interacted",
]


def write_summary_csv(csv_path: Path, all_condition_aggs: List[Dict[str, Any]]) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for agg in all_condition_aggs:
            costs = agg.get("cost_estimates", {})
            row = {
                "site_id": agg["site_id"],
                "domain": agg["domain"],
                "category": agg["category"],
                "condition": agg["condition"],
                "total_bytes_mb": round(agg["total_bytes_mean"] / (1024 * 1024), 6),
                "tracker_bytes_mb": round(agg["tracker_bytes_mean"] / (1024 * 1024), 6),
                "tracker_share_pct": agg["tracker_share_pct_mean"],
                "tracker_share_pct_stdev": agg["tracker_share_pct_stdev"],
                "runs_completed": agg["runs_completed"],
                "runs_failed": agg["runs_failed"],
                "cost_airtel_combo_60gb": costs.get("airtel_combo_60gb", {}).get("estimated_cost_rwf", ""),
                "cost_airtel_daily_1gb": costs.get("airtel_daily_1gb", {}).get("estimated_cost_rwf", ""),
                "cost_mtn_daily_1500mb": costs.get("mtn_daily_1500mb", {}).get("estimated_cost_rwf", ""),
                "cost_rura_mtn_inbundle": costs.get("rura_mtn_inbundle", {}).get("estimated_cost_rwf", ""),
                "cost_mtn_out_of_bundle": costs.get("mtn_out_of_bundle", {}).get("estimated_cost_rwf", ""),
                "cost_airtel_out_of_bundle": costs.get("airtel_out_of_bundle", {}).get("estimated_cost_rwf", ""),
                "banner_found": agg.get("banner_found", False),
                "banner_interacted": agg.get("banner_interacted", False),
            }
            writer.writerow(row)
    log.info(f"Summary CSV written → {csv_path}")


# ---------------------------------------------------------------------------
# Experiment loop — Task 3
# ---------------------------------------------------------------------------

CONDITIONS = ["Initial_Load", "Rejected", "Accepted"]
REPETITIONS = 3


async def run_site(
    site: Dict[str, Any],
    output_dirs: Dict[str, Path],
    run_log_path: Path,
    timeout_ms: int = 30000,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Run all 3 conditions × 3 repetitions for one site.
    Returns (final_site_agg, list_of_condition_aggs).
    """
    condition_aggs: Dict[str, Dict[str, Any]] = {}
    condition_agg_list: List[Dict[str, Any]] = []

    for condition in CONDITIONS:
        log.info(f"=== {site['domain']} | {condition} ===")
        runs: List[Dict[str, Any]] = []

        for rep in range(1, REPETITIONS + 1):
            log.info(f"  {site['domain']} | {condition} | run {rep}/{REPETITIONS}")
            result = await run_single(site, condition, rep, output_dirs, timeout_ms)
            _write_run_log(run_log_path, site, condition, rep, result)
            runs.append(result)

        cond_agg = aggregate_condition_runs(runs, site, condition)
        agg_path = (
            output_dirs["aggregated"]
            / f"{site['domain'].replace('.', '_')}_{condition}_aggregated.json"
        )
        agg_path.write_text(json.dumps(cond_agg, indent=2), encoding="utf-8")
        log.info(
            f"  Aggregated [{condition}]: tracker_share={cond_agg['tracker_share_pct_mean']:.2f}% "
            f"(±{cond_agg['tracker_share_pct_stdev']:.2f}), "
            f"runs OK={cond_agg['runs_completed']}/FAIL={cond_agg['runs_failed']}"
        )

        condition_aggs[condition] = cond_agg
        condition_agg_list.append(cond_agg)

    site_agg = aggregate_site_conditions(condition_aggs, site)
    site_agg_path = (
        output_dirs["aggregated"]
        / f"{site['domain'].replace('.', '_')}_final_aggregated.json"
    )
    site_agg_path.write_text(json.dumps(site_agg, indent=2), encoding="utf-8")

    return site_agg, condition_agg_list


# ---------------------------------------------------------------------------
# CLI — Task 7 / Section 7
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tracker measurement tool — Paying to Be Watched"
    )
    parser.add_argument(
        "--sites",
        default="data/sites.json",
        help="Path to sites.json (default: data/sites.json)",
    )
    parser.add_argument(
        "--output",
        default="tracker_results/",
        help="Output root directory (default: tracker_results/)",
    )
    parser.add_argument(
        "--tracker-radar",
        default="data/domains/",
        dest="tracker_radar",
        help="Path to DuckDuckGo Tracker Radar domains/ folder (default: data/domains/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Verify paths and print run plan without opening any browsers",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30000,
        help="Navigation timeout in ms (default: 30000)",
    )
    return parser.parse_args()


def setup_output_dirs(output_root: Path) -> Dict[str, Path]:
    dirs = {
        "root": output_root,
        "hars": output_root / "hars",
        "logs": output_root / "logs",
        "aggregated": output_root / "aggregated",
        "blocklists": output_root / "blocklists",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def setup_logging(output_root: Path) -> None:
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt)
    # Also log to run_log.txt as plain INFO lines (the structured per-run log is separate)
    root_logger = logging.getLogger()
    fh = logging.FileHandler(output_root / "run_log.txt", encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt))
    root_logger.addHandler(fh)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    args = parse_args()

    sites_path = Path(args.sites)
    output_root = Path(args.output)
    radar_dir = Path(args.tracker_radar)

    output_dirs = setup_output_dirs(output_root)
    setup_logging(output_root)

    run_log_path = output_root / "run_log.txt"

    # Validate input paths
    if not sites_path.exists():
        log.error(f"sites.json not found: {sites_path}")
        return
    if not radar_dir.exists():
        log.error(f"Tracker Radar directory not found: {radar_dir}")
        return

    sites: List[Dict[str, Any]] = json.loads(sites_path.read_bytes())
    log.info(f"Loaded {len(sites)} sites from {sites_path}")

    # Build tracker domain set (Task 1)
    easyprivacy_cache = output_dirs["blocklists"] / "easyprivacy_domains.txt"
    global TRACKER_DOMAINS
    TRACKER_DOMAINS = build_tracker_domains(easyprivacy_cache, radar_dir)

    if args.dry_run:
        print("\n=== DRY RUN — no browsers will be opened ===\n")
        print(f"Sites file    : {sites_path.resolve()}")
        print(f"Output dir    : {output_root.resolve()}")
        print(f"Tracker Radar : {radar_dir.resolve()}")
        print(f"EasyPrivacy cache: {easyprivacy_cache.resolve()}")
        print(f"Tracker domains loaded: {len(TRACKER_DOMAINS):,}")
        print(f"Sites to process: {len(sites)}")
        print(f"Conditions: {CONDITIONS}")
        print(f"Repetitions per condition: {REPETITIONS}")
        total_runs = len(sites) * len(CONDITIONS) * REPETITIONS
        print(f"Total browser sessions: {total_runs}")
        print(f"\nSite list:")
        for s in sites:
            print(f"  [{s['id']:2d}] {s['domain']:<30s} {s['category']}")
        print("\n=== DRY RUN COMPLETE — paths OK ===")
        return

    all_condition_aggs: List[Dict[str, Any]] = []

    for site in sites:
        log.info(f"\n{'='*60}")
        log.info(f"Processing site {site['id']}/{len(sites)}: {site['domain']}")
        log.info(f"{'='*60}")

        try:
            _site_agg, cond_aggs = await run_site(
                site, output_dirs, run_log_path, args.timeout
            )
            all_condition_aggs.extend(cond_aggs)
        except Exception as exc:
            log.error(f"Unexpected error processing site {site['domain']}: {exc}")
            # Record skeleton aggregations so the CSV row still appears
            for condition in CONDITIONS:
                all_condition_aggs.append({
                    "site_id": site["id"],
                    "domain": site["domain"],
                    "category": site.get("category", ""),
                    "condition": condition,
                    "total_bytes_mean": 0.0,
                    "tracker_bytes_mean": 0.0,
                    "tracker_share_pct_mean": 0.0,
                    "tracker_share_pct_stdev": 0.0,
                    "runs_completed": 0,
                    "runs_failed": REPETITIONS,
                    "banner_found": False,
                    "banner_interacted": False,
                    "cost_estimates": _compute_cost_estimates(0.0),
                })

    # Task 6: Write summary CSV
    csv_path = output_root / "results_summary.csv"
    write_summary_csv(csv_path, all_condition_aggs)

    log.info("All sites complete.")


if __name__ == "__main__":
    asyncio.run(main())
