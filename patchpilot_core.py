"""PatchPilot core logic. No Streamlit and no network calls here, so it is easy to test."""
from __future__ import annotations

import html
import re
from urllib.parse import quote, urlparse

from patchpilot_content import PATH_NOTES, REBOOT_HINT, WAVES, WORKFLOWS

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
KB_RE = re.compile(r"\bKB\s?-?(\d{6,8})\b", re.I)
MONTH_RE = re.compile(
    r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20\d{2})\b",
    re.I,
)


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def to_float(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def clean_text(s) -> str:
    s = re.sub(r"<[^>]+>", " ", str(s or ""))
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def version_key(v: str) -> tuple:
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts[:6]) or (0,)


VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)+(?:[-_+.]?[A-Za-z0-9]+)*$")


def is_version(v: str) -> bool:
    """True for things like 10.2.9-h1 or 24.2. False for commit hashes and hotfix names."""
    v = str(v).strip()
    if not v or len(v) > 40:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{7,}", v):
        return False
    return bool(VERSION_RE.match(v))


def max_version(versions) -> str:
    versions = [v for v in versions if v]
    return max(versions, key=version_key) if versions else ""


# ----------------------------------------------------------------------------
# Priority (swap this block for your Risk Calc logic to keep both apps aligned)
# ----------------------------------------------------------------------------
def compute_priority(kev, epss, cvss, internet_facing: bool = False) -> str:
    epss = to_float(epss) or 0.0
    cvss = to_float(cvss) or 0.0
    if kev or epss >= 0.70:
        level = 1
    elif cvss >= 9.0 or epss >= 0.30:
        level = 2
    elif cvss >= 7.0 or epss >= 0.10:
        level = 3
    else:
        level = 4
    if internet_facing and level > 1:
        level -= 1
    return f"P{level}"


def priority_reasons(kev, epss, cvss, internet_facing: bool = False) -> list[str]:
    reasons = []
    if kev:
        reasons.append("Listed in CISA KEV (exploited in the wild)")
    e = to_float(epss)
    if e is not None:
        reasons.append(f"EPSS {e * 100:.1f}% chance of exploitation in the next 30 days")
    c = to_float(cvss)
    if c is not None:
        reasons.append(f"CVSS base score {c:.1f}")
    if internet_facing:
        reasons.append("Marked internet-facing (priority raised one level where possible)")
    return reasons


def priority_rank(p: str) -> int:
    try:
        return int(str(p)[1])
    except (ValueError, IndexError):
        return 4


def path_for_priority(p: str) -> str:
    return "Emergency" if priority_rank(p) == 1 else "Normal"


# ----------------------------------------------------------------------------
# Parsers for public data
# ----------------------------------------------------------------------------
def parse_nvd(data):
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    desc = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    cvss = severity = vector = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0]
            d = m.get("cvssData") or {}
            cvss = to_float(d.get("baseScore"))
            severity = d.get("baseSeverity") or m.get("baseSeverity")
            vector = d.get("vectorString")
            break
    refs = [
        {"url": r.get("url", ""), "tags": r.get("tags") or []}
        for r in cve.get("references", [])
    ]
    return {
        "id": cve.get("id"),
        "description": clean_text(desc),
        "cvss": cvss,
        "severity": severity,
        "vector": vector,
        "published": (cve.get("published") or "")[:10],
        "modified": (cve.get("lastModified") or "")[:10],
        "status": cve.get("vulnStatus"),
        "references": refs,
    }


def parse_nvd_list(data) -> list[dict]:
    out = []
    for v in (data or {}).get("vulnerabilities") or []:
        parsed = parse_nvd({"vulnerabilities": [v]})
        if parsed:
            out.append(parsed)
    return out


def _cvss_from_metrics(metrics):
    for m in metrics or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            d = m.get(key)
            if d and d.get("baseScore") is not None:
                return to_float(d["baseScore"])
    return None


def parse_cve_record(rec) -> dict:
    """Parse a CVE JSON 5 record (cveawg.mitre.org / CVE.org)."""
    out = {
        "vendor": "",
        "product": "",
        "products": [],
        "fixed": [],  # list of (product, version) where version looks like a real version
        "fixed_other": [],  # hotfix names, commit hashes and similar
        "solutions": [],
        "workarounds": [],
        "references": [],
        "cvss": None,
        "title": "",
    }
    if not rec:
        return out
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    blocks = [cna] + list(containers.get("adp") or [])
    out["title"] = clean_text(cna.get("title"))

    affected_lists = [b.get("affected") for b in blocks if b.get("affected")]
    affected = affected_lists[0] if affected_lists else []
    seen_fixed = set()

    def add_fixed(product, ver):
        pair = (product, ver)
        if pair in seen_fixed:
            return
        seen_fixed.add(pair)
        out["fixed" if is_version(ver) else "fixed_other"].append(pair)

    for a in affected:
        vendor = clean_text(a.get("vendor"))
        product = clean_text(a.get("product"))
        if vendor.lower() in ("n/a", "unspecified", "unknown"):
            vendor = ""
        if product.lower() in ("n/a", "unspecified", "unknown"):
            product = ""
        if not out["vendor"] and vendor:
            out["vendor"] = vendor
        if not out["product"] and product:
            out["product"] = product
        if product and product not in out["products"]:
            out["products"].append(product)
        for v in a.get("versions") or []:
            status = str(v.get("status", "")).lower()
            ver = str(v.get("version", "")).strip()
            if status == "unaffected" and ver and ver.lower() not in ("0", "unspecified", "n/a", "*"):
                add_fixed(product, ver)
            lt = str(v.get("lessThan", "")).strip()
            if status == "affected" and lt and lt.lower() not in ("unspecified", "*", "n/a"):
                add_fixed(product, lt)

    for s in cna.get("solutions") or []:
        txt = clean_text(s.get("value"))
        if txt:
            out["solutions"].append(txt)
    for w in cna.get("workarounds") or []:
        txt = clean_text(w.get("value"))
        if txt:
            out["workarounds"].append(txt)

    for b in blocks:
        c = _cvss_from_metrics(b.get("metrics"))
        if c is not None:
            out["cvss"] = c
            break

    for r in cna.get("references") or []:
        out["references"].append({"url": r.get("url", ""), "tags": r.get("tags") or []})
    return out


# ----------------------------------------------------------------------------
# References and vendor links
# ----------------------------------------------------------------------------
FIX_TAGS = {"vendor advisory", "patch", "mitigation", "release notes"}

VENDOR_DOMAINS = {
    "msrc.microsoft.com": "Microsoft",
    "support.microsoft.com": "Microsoft",
    "portal.msrc.microsoft.com": "Microsoft",
    "sec.cloudapps.cisco.com": "Cisco",
    "tools.cisco.com": "Cisco",
    "cisco.com": "Cisco",
    "security.paloaltonetworks.com": "Palo Alto Networks",
    "fortiguard.com": "Fortinet",
    "support.fortinet.com": "Fortinet",
    "my.f5.com": "F5",
    "support.f5.com": "F5",
    "supportportal.juniper.net": "Juniper",
    "kb.juniper.net": "Juniper",
    "support.broadcom.com": "Broadcom / VMware",
    "vmware.com": "VMware",
    "access.redhat.com": "Red Hat",
    "ubuntu.com": "Ubuntu",
    "security-tracker.debian.org": "Debian",
    "debian.org": "Debian",
    "suse.com": "SUSE",
    "helpx.adobe.com": "Adobe",
    "oracle.com": "Oracle",
    "chromereleases.googleblog.com": "Google Chrome",
    "mozilla.org": "Mozilla",
    "openssl.org": "OpenSSL",
    "checkpoint.com": "Check Point",
    "apache.org": "Apache",
}


def classify_references(refs):
    """Split references into (fix_related, other). Only http(s) links are kept."""
    fix, other, seen = [], [], set()
    for r in refs or []:
        url = str(r.get("url", "")).strip()
        if not url.lower().startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        tags = {str(t).lower().replace("-", " ") for t in (r.get("tags") or [])}
        host = urlparse(url).netloc.lower()
        vendor = next(
            (v for d, v in VENDOR_DOMAINS.items() if host == d or host.endswith("." + d)), ""
        )
        item = {"url": url, "host": host, "vendor": vendor, "tags": sorted(tags)}
        if (tags & FIX_TAGS) or vendor:
            fix.append(item)
        else:
            other.append(item)
    return fix, other


def vendor_links(cve_id: str, platform: str, vendor_text: str = "") -> list[tuple[str, str]]:
    """Predictable links to useful places. Every URL is built from the CVE ID only."""
    cve_id = cve_id.upper()
    t = (vendor_text or "").lower()
    links = [
        ("NVD entry", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        ("CVE.org record", f"https://www.cve.org/CVERecord?id={cve_id}"),
    ]
    if platform == "Windows" or "microsoft" in t:
        links.append(("Microsoft Security Update Guide", f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"))
    if platform == "Linux":
        links += [
            ("Red Hat CVE page", f"https://access.redhat.com/security/cve/{cve_id}"),
            ("Ubuntu CVE page", f"https://ubuntu.com/security/{cve_id}"),
            ("Debian security tracker", f"https://security-tracker.debian.org/tracker/{cve_id}"),
        ]
    if "palo alto" in t or "pan-os" in t:
        links.append(("Palo Alto Networks advisory", f"https://security.paloaltonetworks.com/{cve_id}"))
    if "cisco" in t:
        links.append(("Cisco security advisories", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"))
    if "fortinet" in t or "forti" in t:
        links.append(("Fortinet PSIRT advisories", "https://www.fortiguard.com/psirt"))
    query = quote(f"{cve_id} {vendor_text} security advisory fixed version".strip())
    links.append(("Search for the vendor advisory", f"https://www.google.com/search?q={query}"))
    return links


def kb_links(kb: str) -> list[tuple[str, str]]:
    kb = re.sub(r"\D", "", kb)
    return [
        ("Microsoft Update Catalog", f"https://www.catalog.update.microsoft.com/Search.aspx?q=KB{kb}"),
        ("Microsoft Support article", f"https://support.microsoft.com/help/{kb}"),
    ]


# ----------------------------------------------------------------------------
# Patch downloads that need no login
# ----------------------------------------------------------------------------
SUPPORT_KB_URL_RE = re.compile(r"support\.microsoft\.com/[^\s\"']*?(\d{6,8})\b", re.I)


def extract_kbs(*texts) -> list[str]:
    """Pull Microsoft KB numbers out of reference URLs and text (digits only, in order of appearance)."""
    found: list[str] = []
    for t in texts:
        t = str(t or "")
        for m in list(KB_RE.finditer(t)) + list(SUPPORT_KB_URL_RE.finditer(t)):
            kb = m.group(1)
            if kb not in found:
                found.append(kb)
    return found


# Public vendor download pages that work without an account: (regex, label, url)
PUBLIC_DOWNLOADS = [
    (r"google chrome|\bchrome\b|chromium", "Google Chrome download page", "https://www.google.com/chrome/"),
    (r"firefox", "Mozilla Firefox, all platforms and languages", "https://www.mozilla.org/firefox/all/"),
    (r"thunderbird", "Mozilla Thunderbird, all platforms", "https://www.thunderbird.net/thunderbird/all/"),
    (r"microsoft edge", "Microsoft Edge for business", "https://www.microsoft.com/edge/business/download"),
    (r"openssl", "OpenSSL source downloads", "https://www.openssl.org/source/"),
    (r"openssh", "OpenSSH portable releases", "https://www.openssh.com/portable.html"),
    (r"linux kernel|\bkernel\.org\b", "Linux kernel archive", "https://www.kernel.org/"),
    (r"7-?zip", "7-Zip download page", "https://www.7-zip.org/download.html"),
    (r"\bvlc\b", "VLC download page", "https://www.videolan.org/vlc/"),
    (r"apache http|apache httpd|httpd", "Apache HTTP Server downloads", "https://httpd.apache.org/download.cgi"),
    (r"putty", "PuTTY latest release", "https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html"),
    (r"notepad\+\+", "Notepad++ downloads", "https://notepad-plus-plus.org/downloads/"),
    (r"winscp", "WinSCP download page", "https://winscp.net/eng/download.php"),
    (r"wireshark", "Wireshark download page", "https://www.wireshark.org/download.html"),
    (r"virtualbox", "VirtualBox downloads", "https://www.virtualbox.org/wiki/Downloads"),
    (r"\bgit\b", "Git downloads", "https://git-scm.com/downloads"),
    (r"\bzoom\b", "Zoom download center", "https://zoom.us/download"),
]

# Vendors whose patch files sit behind a support-account login
LOGIN_REQUIRED_RE = re.compile(
    r"cisco|palo alto|pan-?os|fortinet|fortios|fortigate|\bf5\b|big-?ip|juniper|junos|vmware|broadcom|esxi|vcenter|"
    r"check ?point|netscaler|citrix|sonicwall|oracle|sap\b|ivanti|pulse secure",
    re.I,
)


def download_options(platform: str, text: str, kbs=None) -> list[dict]:
    """Where to get the patch itself. Every link is a public page; vendors that need a login say so.

    Returns [{"label", "url", "note"}]. url may be empty for plain-text guidance.
    """
    kbs = list(kbs or [])
    t = (text or "").lower()
    out: list[dict] = []
    for kb in kbs[:4]:
        out.append({
            "label": f"Microsoft Update Catalog: KB{kb}",
            "url": f"https://www.catalog.update.microsoft.com/Search.aspx?q=KB{kb}",
            "note": "No sign-in. Pick your OS build, press Download.",
        })
    if platform == "Windows" and not kbs:
        out.append({
            "label": "Microsoft Update Catalog (search by KB)",
            "url": "https://www.catalog.update.microsoft.com/",
            "note": "No sign-in. The Security Update Guide link shows the KB for each product.",
        })
    for rx, label, url in PUBLIC_DOWNLOADS:
        if re.search(rx, t):
            out.append({"label": label, "url": url, "note": "Public page, no login."})
    if platform == "Linux" and not any(o["url"] for o in out):
        out.append({"label": "Distribution package repositories", "url": "",
                    "note": "Install the fixed package with your package manager. See the distro advisory links."})
    if LOGIN_REQUIRED_RE.search(t) and platform != "Windows":
        out.append({"label": "Vendor download", "url": "",
                    "note": "This vendor requires a support-account login. Open the advisory for the exact file."})
    if not out:
        out.append({"label": "Vendor download", "url": "",
                    "note": "No public download page known. Use the vendor advisory links."})
    return out


# ----------------------------------------------------------------------------
# Platform and product detection
# ----------------------------------------------------------------------------
def _platform_from_text(text: str):
    t = (text or "").lower()
    if not t.strip():
        return None
    if re.search(r"\besxi\b|vcenter|vsphere|vmware|broadcom", t):
        return "VMware ESXi / vCenter"
    if re.search(
        r"cisco|palo alto|pan-?os|globalprotect|fortinet|fortios|fortigate|fortiproxy|juniper|junos|"
        r"big-?ip|\bf5\b|check ?point|arista|aruba|netscaler|sonicwall|firewall|router",
        t,
    ):
        return "Network device"
    if re.search(r"microsoft|windows|\.net|sharepoint|exchange server|active directory", t):
        return "Windows"
    if re.search(
        r"linux|ubuntu|debian|red hat|rhel|centos|suse|alma|rocky|kernel|openssl|openssh|glibc|systemd",
        t,
    ):
        return "Linux"
    return None


def detect_platform(vendor: str = "", product: str = "", description: str = "") -> str:
    for text in (f"{vendor} {product}", description):
        p = _platform_from_text(text)
        if p:
            return p
    return "Application / other"


# (label, platform, regex): first match wins
PRODUCT_RULES = [
    ("VMware ESXi / vCenter", "VMware ESXi / vCenter", r"\besxi\b|vcenter|vsphere"),
    ("Palo Alto PAN-OS", "Network device", r"pan-?os|palo alto|globalprotect"),
    ("Cisco IOS / IOS XE / NX-OS", "Network device", r"cisco\s+ios|ios\s*xe|ios\s*xr|nx-?os"),
    ("Cisco (other products)", "Network device", r"\bcisco\b|firepower|anyconnect"),
    ("Fortinet FortiOS and products", "Network device", r"fortios|fortigate|fortinet|fortiproxy|fortimanager|fortianalyzer"),
    ("F5 BIG-IP", "Network device", r"big-?ip|\bf5\b"),
    ("Juniper Junos", "Network device", r"junos|juniper"),
    ("Check Point", "Network device", r"check ?point"),
    ("Google Chrome", "Application / other", r"google chrome|\bchrome\b|chromium"),
    ("Mozilla Firefox / Thunderbird", "Application / other", r"firefox|thunderbird"),
    ("Microsoft Edge", "Windows", r"microsoft edge"),
    ("Microsoft Office", "Windows", r"microsoft (office|word|excel|outlook|powerpoint|365)"),
    ("Microsoft Exchange", "Windows", r"exchange server|microsoft exchange"),
    ("Microsoft SQL Server", "Windows", r"sql server"),
    ("Microsoft Windows", "Windows", r"windows|\.net framework|microsoft (security|update)"),
    ("Adobe products", "Application / other", r"adobe|acrobat"),
    ("Java (Oracle JDK/JRE)", "Application / other", r"\bjava\b|\bjre\b|\bjdk\b"),
    ("Apache products", "Application / other", r"apache|tomcat|log4j|struts"),
    ("OpenSSL", "Linux", r"openssl"),
    ("OpenSSH", "Linux", r"openssh"),
    ("Linux kernel", "Linux", r"linux kernel|\bkernel\b"),
    ("Red Hat family", "Linux", r"red hat|rhel|centos|alma ?linux|rocky"),
    ("Ubuntu", "Linux", r"ubuntu"),
    ("Debian", "Linux", r"debian"),
    ("SUSE", "Linux", r"suse"),
]


def classify_title(text: str):
    t = (text or "").lower()
    if not t.strip():
        return None
    for label, platform, rx in PRODUCT_RULES:
        if re.search(rx, t):
            return label, platform
    return None


def product_label(vendor: str, product: str) -> str:
    v, p = (vendor or "").strip(), (product or "").strip()
    if v.lower().startswith("microsoft") and p.lower().startswith("windows"):
        return "Microsoft Windows"
    # keep the name up to the first version-looking token
    p = re.split(r"\s+(?=v?\d|version\b|for\b|before\b)", p, maxsplit=1)[0].strip()
    if not p:
        return v
    if v and v.lower() not in p.lower():
        return f"{v} {p}"
    return p


def bundle_key(title: str, info: dict):
    """Return (label, platform) for a finding, or (None, None) when nothing is known."""
    title = title or ""
    kb = KB_RE.search(title)
    if kb:
        return f"Microsoft KB{kb.group(1)}", "Windows"
    cls = classify_title(title)
    if cls:
        label, platform = cls
        if platform == "Windows":
            m = MONTH_RE.search(title)
            if m:
                label = f"{label} ({m.group(1).title()} {m.group(2)})"
        return label, platform
    vendor, product = info.get("vendor", ""), info.get("product", "")
    if vendor or product:
        return product_label(vendor, product), detect_platform(vendor, product, info.get("description", ""))
    return None, None


# ----------------------------------------------------------------------------
# Bulk input parsing
# ----------------------------------------------------------------------------
def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        if v != v:  # NaN
            return ""
        if v.is_integer():
            return str(int(v))
    return str(v).strip()


def parse_bulk_text(text: str) -> list[dict]:
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(line)))
        rest = CVE_RE.sub(" ", line)
        rest = re.sub(r"^[\s,;|\t-]+|[\s,;|\t-]+$", "", rest)
        qid = ""
        m = re.match(r"^(\d{4,7})\b[\s,;|\t:-]*(.*)$", rest)
        if m:
            qid, rest = m.group(1), m.group(2).strip()
        title = rest
        if cves:
            for c in cves:
                rows.append({"cve": c, "title": title, "qid": qid})
        elif title or qid:
            rows.append({"cve": "", "title": title, "qid": qid})
    return rows


def detect_columns(columns) -> dict:
    lower = {str(c).strip().lower(): c for c in columns}
    cols = {}
    cols["cve"] = next((c for k, c in lower.items() if "cve" in k), None)
    cols["qid"] = next(
        (
            c
            for k, c in lower.items()
            if k in ("qid", "qid id", "plugin id", "pluginid", "plugin_id", "plugin") or k.startswith("qid")
        ),
        None,
    )
    title = None
    for word in ("title", "name", "synopsis", "vulnerability", "finding"):
        title = next((c for k, c in lower.items() if word in k and c != cols["cve"] and c != cols["qid"]), None)
        if title is not None:
            break
    cols["title"] = title
    return cols


def rows_from_records(records, columns) -> list[dict]:
    cols = detect_columns(columns)
    rows = []
    for rec in records:
        if not any(cols.values()):
            text = " ".join(_s(v) for v in rec.values())
            for c in dict.fromkeys(x.upper() for x in CVE_RE.findall(text)):
                rows.append({"cve": c, "title": "", "qid": ""})
            continue
        cve_text = _s(rec.get(cols["cve"])) if cols["cve"] is not None else ""
        title = _s(rec.get(cols["title"])) if cols["title"] is not None else ""
        qid = _s(rec.get(cols["qid"])) if cols["qid"] is not None else ""
        cves = list(dict.fromkeys(c.upper() for c in (CVE_RE.findall(cve_text) or CVE_RE.findall(title))))
        if cves:
            rows.extend({"cve": c, "title": title, "qid": qid} for c in cves)
        elif title or qid:
            rows.append({"cve": "", "title": title, "qid": qid})
    return rows


# ----------------------------------------------------------------------------
# Bundling
# ----------------------------------------------------------------------------
def build_bundles(rows, enrich: dict, internet: bool = False):
    """Group findings into patch bundles.

    rows: [{"cve","title","qid"}]; enrich: {cve: {"kev","epss","cvss","vendor","product","fixed",...}}
    Returns (bundles, cve_rows, unmapped).
    """
    groups: dict[str, dict] = {}
    cve_rows, unmapped, seen = [], [], set()

    for r in rows:
        cve = (r.get("cve") or "").upper()
        title = r.get("title", "")
        qid = r.get("qid", "")
        info = enrich.get(cve, {}) if cve else {}
        label, platform = bundle_key(title, info)
        if not label:
            if cve:
                label, platform = "Unknown product (needs lookup)", "Unknown"
            else:
                unmapped.append({"QID": qid, "Title": title, "CVE": ""})
                continue
        ident = cve or f"{qid}|{title}"
        if (label, ident) in seen:
            continue
        seen.add((label, ident))

        if cve:
            prio = compute_priority(info.get("kev"), info.get("epss"), info.get("cvss"), internet)
            scored = True
        else:
            prio, scored = "P3", False
        rank = priority_rank(prio)

        g = groups.setdefault(
            label,
            {
                "platform": platform,
                "cves": [],
                "kev": 0,
                "epss": 0.0,
                "cvss": 0.0,
                "rank": 4,
                "fixed": [],
                "other": set(),
                "unscored": 0,
                "findings": 0,
            },
        )
        g["findings"] += 1
        g["rank"] = min(g["rank"], rank)
        if cve:
            g["cves"].append(cve)
            g["kev"] += 1 if info.get("kev") else 0
            g["epss"] = max(g["epss"], to_float(info.get("epss")) or 0.0)
            g["cvss"] = max(g["cvss"], to_float(info.get("cvss")) or 0.0)
            g["fixed"].extend(v for _, v in (info.get("fixed") or []))
            g["other"].update(v for _, v in (info.get("fixed_other") or []))
        else:
            g["unscored"] += 1

        cve_rows.append(
            {
                "Bundle": label,
                "CVE": cve,
                "QID": qid,
                "Title": title,
                "Priority": prio if scored else "P3 (unscored)",
                "KEV": "Yes" if info.get("kev") else "",
                "EPSS %": round((to_float(info.get("epss")) or 0.0) * 100, 1) if cve else None,
                "CVSS": to_float(info.get("cvss")) if cve else None,
            }
        )

    bundles = []
    for label, g in groups.items():
        bundles.append(
            {
                "Bundle": label,
                "Platform": g["platform"],
                "Priority": f"P{g['rank']}",
                "Wave": WAVES[g["rank"]],
                "CVEs": len(set(g["cves"])),
                "Findings": g["findings"],
                "KEV": g["kev"],
                "Max EPSS %": round(g["epss"] * 100, 1),
                "Max CVSS": round(g["cvss"], 1) if g["cvss"] else None,
                "Fix target": max_version(g["fixed"]),
                "Fix notes": (f"{len(g['other'])} hotfix/commit reference(s) in CVE records" if g["other"] else ""),
                "Reboot": REBOOT_HINT.get(g["platform"], REBOOT_HINT["Unknown"]),
                "Unscored": g["unscored"],
                "_cves": sorted(set(g["cves"])),
            }
        )
    bundles.sort(key=lambda b: (priority_rank(b["Priority"]), -b["KEV"], -b["CVEs"], b["Bundle"]))
    for i, b in enumerate(bundles, 1):
        b["ID"] = f"B{i:02d}"
    return bundles, cve_rows, unmapped


# ----------------------------------------------------------------------------
# Change request text
# ----------------------------------------------------------------------------
def change_request_text(
    *,
    title: str,
    cves,
    priority: str,
    platform: str,
    path: str,
    fix_target: str = "",
    kev_count: int = 0,
    links=None,
    sla_days: int | None = None,
) -> str:
    cves = list(cves or [])
    wf = WORKFLOWS.get(platform) or WORKFLOWS["Application / other"]
    shown = ", ".join(cves[:25]) + (f" and {len(cves) - 25} more" if len(cves) > 25 else "")
    lines = [
        f"CHANGE REQUEST: {title}",
        f"Change type: {'Emergency' if path == 'Emergency' else 'Normal / standard patch cycle'}",
        f"Priority: {priority}" + (f" (target within {sla_days} days)" if sla_days else ""),
        f"Platform: {platform}",
        "",
        "Reason for change",
        f"- Remediates {len(set(cves)) or 'the listed'} vulnerabilit{'y' if len(set(cves)) == 1 else 'ies'}: {shown or 'see references'}",
    ]
    if kev_count:
        lines.append(f"- {kev_count} listed in the CISA Known Exploited Vulnerabilities catalog (exploited in the wild)")
    lines += [
        f"- Fix / target version: {fix_target or 'Per vendor advisory (see references)'}",
        "",
        "Scope",
        "- Affected systems: [change owner to complete]",
        "- Maintenance window: [change owner to complete]",
        "",
        "Risk if not implemented",
        "- Vulnerable systems stay open to attack; exploitation of these issues can lead to compromise of the affected platform.",
        "",
        "Implementation plan",
    ]
    steps = PATH_NOTES[path] + wf["pre"] + wf["patch"]
    lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    lines += ["", "Validation"] + [f"- {s}" for s in wf["validate"]]
    lines += ["", "Rollback plan"] + [f"- {s}" for s in wf["rollback"]]
    if links:
        lines += ["", "References"] + [f"- {name}: {url}" for name, url in links]
    lines += ["", "Approvals", "- [ ] Change owner   - [ ] Application owner   - [ ] Change approver"]
    return "\n".join(lines)
