# pplt-tracker-audit

> **Paying to Be Watched: How Hidden Trackers Eat Rwandans' Mobile Data**  
> Swafiyah Wanjiru Gichuki & Ange Kimberly Mukeshimana

A Playwright-based script that audits third-party tracker traffic on Rwandan websites under three consent conditions:

| Condition | Description |
|-----------|-------------|
| `Initial_Load` | No consent interaction - raw page load |
| `Rejected` | All non-essential cookies rejected |
| `Accepted` | All cookies accepted |

For each (URL × condition) pair the script saves:
- A **HAR archive** (`tracker_results/hars/`)
- A **JSON summary** with byte counts, tracker share %, and per-request logs (`tracker_results/logs/`)

---

## Installation

```bash
# 1. Install Python dependencies
pip install playwright

# 2. Download the Chromium browser binary
playwright install chromium
```

Python ≥ 3.9 required.

---

## Quick start

```bash
python tracker_measurement.py
```

The four pilot URLs are already configured in `main()`:

```
https://www.igihe.com
https://www.newtimes.co.rw
https://irembo.gov.rw
https://www.bk.rw
```

Results land in `tracker_results/` (created automatically).

---

## Script overview

| Function | Purpose |
|----------|---------|
| `extract_etld_plus_one(url)` | Strips URL to eTLD+1 for domain comparison |
| `is_third_party_tracker(req_url, page_domain)` | Checks request against known tracker domain list |
| `handle_consent_banner(page, action)` | Clicks Reject/Accept on OneTrust, Cookiebot, and common CMP banners |
| `record_website_traffic(url, condition)` | Core audit function - launches browser, records HAR, computes metrics |
| `main()` | Runs all (URL × condition) combinations sequentially |

---

## Output fields (per JSON summary)

```
total_bytes                   — all bytes received on the page
tracker_bytes                 — bytes from known third-party tracker domains
tracker_share_pct             — tracker_bytes / total_bytes × 100
post_reload_tracker_share_pct — same, but only for traffic after consent interaction
```

---

## License

MIT
