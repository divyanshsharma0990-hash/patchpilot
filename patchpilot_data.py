"""PatchPilot data layer: public sources only (NVD, CVE.org, CISA KEV, FIRST EPSS).

No Streamlit imports here. A small thread-safe cache lives at module level, so it
survives Streamlit reruns and works from worker threads.
"""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import patchpilot_core as core

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/"
# Used by the Microsoft Security Update Guide website. Not an officially documented API, so treat as best effort.
MSRC_SUG_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"

HEADERS = {"User-Agent": "PatchPilot/1.0 (patching helper; public data only)"}
CACHE_TTL = 3600  # seconds

_CACHE: dict = {}
_LOCK = threading.Lock()


def _cached(key, fn, ttl=CACHE_TTL):
    now = time.time()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fn()
    if value:  # never cache failures or empty answers
        with _LOCK:
            if len(_CACHE) > 5000:
                _CACHE.clear()
            _CACHE[key] = (now, value)
    return value


def _get_json(url, params=None, headers=None, timeout=25):
    h = dict(HEADERS)
    h.update(headers or {})
    for attempt in range(2):
        try:
            r = requests.get(url, params=params, headers=h, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 503) and attempt == 0:
                time.sleep(2)
                continue
            return None
        except (requests.RequestException, ValueError):
            if attempt == 0:
                time.sleep(1)
    return None


# ----------------------------------------------------------------------------
# Individual sources
# ----------------------------------------------------------------------------
def get_kev() -> dict:
    def fetch():
        d = _get_json(KEV_URL, timeout=40)
        if not d:
            return None
        return {v["cveID"].upper(): v for v in d.get("vulnerabilities", []) if v.get("cveID")}

    return _cached("kev", fetch) or {}


def get_epss(cves) -> dict:
    """EPSS per CVE, cached per CVE so single lookups reuse bulk results."""
    cves = sorted({c.upper() for c in cves})
    out, missing = {}, []
    now = time.time()
    with _LOCK:
        for c in cves:
            hit = _CACHE.get(("epss", c))
            if hit and now - hit[0] < CACHE_TTL:
                out[c] = hit[1]
            else:
                missing.append(c)
    for i in range(0, len(missing), 80):
        chunk = missing[i : i + 80]
        d = _get_json(EPSS_URL, params={"cve": ",".join(chunk)})
        for item in (d or {}).get("data", []):
            cve = str(item.get("cve", "")).upper()
            if not cve:
                continue
            val = {"epss": core.to_float(item.get("epss")), "percentile": core.to_float(item.get("percentile"))}
            out[cve] = val
            with _LOCK:
                _CACHE[("epss", cve)] = (now, val)
    return out


def get_nvd_cve(cve_id: str, api_key: str = ""):
    cve_id = cve_id.upper()
    headers = {"apiKey": api_key} if api_key else None

    def fetch():
        return _get_json(NVD_URL, params={"cveId": cve_id}, headers=headers)

    return _cached(("nvd", cve_id), fetch)


def search_nvd(keyword: str, api_key: str = ""):
    headers = {"apiKey": api_key} if api_key else None

    def fetch():
        return _get_json(NVD_URL, params={"keywordSearch": keyword, "resultsPerPage": 20}, headers=headers)

    return _cached(("nvd-kw", keyword.lower()), fetch, ttl=600)


def get_cve_record(cve_id: str):
    cve_id = cve_id.upper()
    return _cached(("rec", cve_id), lambda: _get_json(CVE_RECORD_URL + cve_id, timeout=20))


def get_msrc_kbs(cve_id: str) -> list[str]:
    """Best effort: KB numbers for a Microsoft CVE from the Security Update Guide data.
    Returns [] when the source does not answer or has no KB for this CVE."""
    cve_id = cve_id.upper()

    def fetch():
        d = _get_json(MSRC_SUG_URL, params={"$filter": f"cveNumber eq '{cve_id}'"}, timeout=12)
        if not d:
            return None
        found = []
        for item in d.get("value", []) if isinstance(d, dict) else []:
            for art in item.get("kbArticles") or []:
                if not isinstance(art, dict):
                    continue
                for key in ("articleName", "kbArticle", "articleNumber", "kb", "name"):
                    m = re.fullmatch(r"(?:KB)?\s?(\d{6,8})", str(art.get(key, "")).strip(), re.I)
                    if m and m.group(1) not in found:
                        found.append(m.group(1))
        return found

    return _cached(("msrc-kb", cve_id), fetch) or []


# ----------------------------------------------------------------------------
# Bulk enrichment
# ----------------------------------------------------------------------------
def enrich_cves(cves, max_deep: int = 150, progress=None) -> dict:
    """Fast data for every CVE (KEV + EPSS), deeper data (product, fixed version, CVSS)
    for the riskiest `max_deep` CVEs. `progress(fraction)` is called from the calling thread."""
    cves = sorted({c.upper() for c in cves})
    kev = get_kev()
    epss = get_epss(cves)
    info = {}
    for c in cves:
        k = kev.get(c) or {}
        info[c] = {
            "kev": bool(k),
            "kev_due": k.get("dueDate", ""),
            "ransomware": k.get("knownRansomwareCampaignUse", ""),
            "epss": (epss.get(c) or {}).get("epss"),
            "cvss": None,
            "vendor": "",
            "product": "",
            "fixed": [],
            "fixed_other": [],
            "description": "",
        }

    order = sorted(cves, key=lambda c: (not info[c]["kev"], -(info[c]["epss"] or 0.0)))[: max(0, max_deep)]
    if order:
        done = 0
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(get_cve_record, c): c for c in order}
            for f in as_completed(futures):
                c = futures[f]
                try:
                    rec = core.parse_cve_record(f.result())
                except Exception:
                    rec = None
                if rec:
                    info[c].update(
                        vendor=rec["vendor"],
                        product=rec["product"],
                        fixed=rec["fixed"],
                        fixed_other=rec["fixed_other"],
                        cvss=rec["cvss"],
                        description=rec["title"],
                    )
                done += 1
                if progress:
                    progress(done / len(order))
    return info
