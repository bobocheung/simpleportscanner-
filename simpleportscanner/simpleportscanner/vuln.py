import re
import time
from typing import Dict, List, Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_product_and_version(service: Optional[str], banner: Optional[str]) -> str:
    text = " ".join([service or "", banner or ""]).strip()
    # Simple heuristics: look for tokens like nginx/1.22.1, Apache/2.4.57, OpenSSH_8.9
    m = re.search(r"([A-Za-z][A-Za-z0-9_\-]+)[/\-_ ](\d+(?:\.\d+){0,2})", text)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    # fallback to service only
    return service or (banner or "")[:32]


def check_vulnerabilities(
    service: Optional[str],
    banner: Optional[str],
    *,
    timeout: float = 5.0,
    max_results: int = 3,
) -> List[Dict]:
    """Query NVD by keyword search using best-effort product/version guess.
    Returns a list of dicts with keys: id, score, title, url.
    """
    keyword = _extract_product_and_version(service, banner)
    if not keyword:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max(1, min(max_results, 10)),
        # Simple rate limiting friendliness
        "pubStartDate": None,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=timeout)
        resp.raise_for_status()
    except Exception:
        return []

    data = resp.json()
    vulns: List[Dict] = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        title = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                title = desc.get("value") or ""
                break
        # Score
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            mlist = metrics.get(key)
            if isinstance(mlist, list) and mlist:
                score = mlist[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    break
        if not cve_id:
            continue
        vulns.append(
            {
                "id": cve_id,
                "score": score,
                "title": title[:160],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )
    return vulns