"""
Playwright Web Tracker & Network Traffic Measurement Script
Project: Paying to Be Watched: How Hidden Trackers Eat Rwandans' Mobile Data
Authors: Swafiyah Wanjiru Gichuki & Ange Kimberly Mukeshimana
"""
# tracker_audit.py
# Measures network traffic before/after consent on Rwandan websites

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Page, Response, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

OUTPUT_DIR = Path(__file__).resolve().parent / "tracker_results" if "__file__" in locals() else Path("./tracker_results")
HAR_DIR = OUTPUT_DIR / "hars"
LOG_DIR = OUTPUT_DIR / "logs"

for d in [OUTPUT_DIR, HAR_DIR, LOG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# TODO: Replace with parsed EasyPrivacy + DuckDuckGo Tracker Radar blocklists
KNOWN_TRACKER_DOMAINS = {
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "scorecardresearch.com", "adnxs.com", "rubiconproject.com", "openx.net"
}


def extract_etld_plus_one(url: str) -> str:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return ""
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return hostname
    except Exception:
        return ""


def is_third_party_tracker(request_url: str, page_domain: str) -> bool:
    req_domain = extract_etld_plus_one(request_url)
    if not req_domain or req_domain == page_domain:
        return False
    for tracker_suffix in KNOWN_TRACKER_DOMAINS:
        if req_domain == tracker_suffix or req_domain.endswith(f".{tracker_suffix}"):
            return True
    return False


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
                # wait_for(state="visible") raises TimeoutError if not found within 2s
                await page.locator(selector).wait_for(state="visible", timeout=2000)
                await page.locator(selector).click()
                logging.info(f"Triggered consent {action.upper()} via selector: {selector}")
                return True
            except Exception:
                # Selector not found or not visible — try the next one
                continue

    except Exception as e:
        logging.debug(f"Consent handler ({action}) error: {e}")

    return False


async def record_website_traffic(
    url: str,
    condition: str = "Initial_Load",
    timeout_ms: int = 30000,
) -> Dict[str, Any]:
    page_domain = extract_etld_plus_one(url)
    sanitized_name = page_domain.replace(".", "_")
    har_path = HAR_DIR / f"{sanitized_name}_{condition}.har"

    # Each request record carries a pre_reload flag so pre- and post-reload
    # traffic can be separated during analysis (relevant for Conditions 2 & 3).
    network_requests: List[Dict[str, Any]] = []
    pre_reload = True  # flips to False after the page is reloaded post-consent

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(record_har_path=str(har_path))
        page = await context.new_page()

        async def on_response(res: Response):
            try:
                req = res.request
                content_length = int(res.headers.get("content-length", 0))
                network_requests.append({
                    "url": req.url,
                    "domain": extract_etld_plus_one(req.url),
                    "resource_type": req.resource_type,
                    "status": res.status,
                    "bytes": content_length,
                    "is_third_party_tracker": is_third_party_tracker(req.url, page_domain),
                    # Distinguishes traffic captured before vs. after the consent
                    # interaction + reload (only meaningful for Conditions 2 & 3).
                    "pre_reload": pre_reload,
                })
            except Exception as e:
                logging.debug(f"Error logging response: {e}")

        page.on("response", on_response)

        try:
            # Step 1: Navigate; DOMContentLoaded prevents stalling on live-feed sites
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            # Step 2: Consent banner interaction for Conditions 2 and 3
            if condition in ("Rejected", "Accepted"):
                action = "reject" if condition == "Rejected" else "accept"
                interacted = await handle_consent_banner(page, action=action)
                if interacted:
                    await asyncio.sleep(3)
                    pre_reload = False  # mark subsequent requests as post-reload
                    await page.reload(wait_until="domcontentloaded", timeout=timeout_ms)

            # Step 3: Non-blocking networkidle wait (capped at 10 s)
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

            # Step 4: Mandatory 5-second settling window for delayed tracker injections
            await asyncio.sleep(5)

        except Exception as err:
            logging.error(f"Navigation error on {url} [{condition}]: {err}")

        await context.close()
        await browser.close()

    # --- Metrics (computed over ALL requests; filter by pre_reload in analysis) ---
    total_bytes = sum(r["bytes"] for r in network_requests)
    tracker_requests = [r for r in network_requests if r["is_third_party_tracker"]]
    tracker_bytes = sum(r["bytes"] for r in tracker_requests)
    tracker_share_pct = (tracker_bytes / total_bytes * 100) if total_bytes > 0 else 0.0

    # Post-reload only (the traffic state after a consent decision was made)
    post_requests = [r for r in network_requests if not r["pre_reload"]]
    post_tracker_bytes = sum(r["bytes"] for r in post_requests if r["is_third_party_tracker"])
    post_total_bytes = sum(r["bytes"] for r in post_requests)
    post_tracker_share_pct = (
        (post_tracker_bytes / post_total_bytes * 100) if post_total_bytes > 0 else 0.0
    )

    summary = {
        "target_url": url,
        "page_domain": page_domain,
        "condition": condition,
        "total_requests": len(network_requests),
        "total_bytes": total_bytes,
        "tracker_requests": len(tracker_requests),
        "tracker_bytes": tracker_bytes,
        "tracker_share_pct": round(tracker_share_pct, 2),
        # Post-reload figures isolate traffic after the consent choice was made
        "post_reload_total_bytes": post_total_bytes,
        "post_reload_tracker_bytes": post_tracker_bytes,
        "post_reload_tracker_share_pct": round(post_tracker_share_pct, 2),
        "har_file": str(har_path),
        "requests_log": network_requests,
    }

    summary_path = LOG_DIR / f"{sanitized_name}_{condition}_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logging.info(
        f"[{condition}] {page_domain} — "
        f"tracker share: {tracker_share_pct:.1f}% (all), "
        f"{post_tracker_share_pct:.1f}% (post-reload)"
    )
    return summary


async def main():
    candidate_urls = [
        "https://www.igihe.com",
        "https://www.newtimes.co.rw",
        "https://irembo.gov.rw",
        "https://www.bk.rw",
    ]
    conditions = ["Initial_Load", "Rejected", "Accepted"]
    for target in candidate_urls:
        for cond in conditions:
            logging.info(f"Running audit: {target} | condition: {cond}")
            await record_website_traffic(target, condition=cond)


if __name__ == "__main__":
    asyncio.run(main())