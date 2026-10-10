"""UI smoke test with a stand-in for Streamlit and fake network data.

Streamlit is not needed. It runs app.py end to end for several scenarios and fails on any exception.
Run with:  python tests/smoke_ui.py
"""
import importlib
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)


class Ns:
    """Stand-in for the streamlit module. Records what the app renders."""

    def __init__(self):
        self.reset()

    def reset(self, query=None, text=None, button=False):
        self.query_params = dict(query or {})
        self.overrides = dict(text or {})
        self.button_pressed = button
        self.session_state = {}
        self.md, self.calls = [], []

    # --- context-manager friendly "container"
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def __getitem__(self, i): return self
    def __iter__(self): return iter([self, self, self, self])

    # --- widgets that return values
    def text_input(self, label, value="", **k): return self.overrides.get(k.get("key") or label, value)
    def text_area(self, label, **k): return self.overrides.get(k.get("key") or label, "")
    def toggle(self, label, value=False, **k): return value
    def number_input(self, label, value=0, **k): return value
    def slider(self, label, mn, mx, value=0, *a, **k): return value
    def selectbox(self, label, options, index=0, **k):
        options = list(options); return options[index] if options else None
    def radio(self, label, options, index=0, **k): return list(options)[index]
    def file_uploader(self, *a, **k): return None
    def button(self, *a, **k): return self.button_pressed
    def form_submit_button(self, *a, **k): return False
    def columns(self, spec, **k): return [self] * (len(spec) if hasattr(spec, "__len__") else int(spec))
    def tabs(self, labels): return [self] * len(labels)
    def markdown(self, body, **k): self.md.append(str(body))
    def cache_resource(self, *a, **k): return a[0] if a and callable(a[0]) else (lambda f: f)

    def __getattr__(self, name):          # everything else just records the call
        def fn(*a, **k):
            self.calls.append((name, a, k)); return self
        return fn


ns = Ns()
fake = types.ModuleType("streamlit")
fake.__getattr__ = lambda name: getattr(ns, name)
sys.modules["streamlit"] = fake

import patchpilot_data as data  # noqa: E402

NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T00:00:00",
       "descriptions": [{"lang": "en", "value": "Command injection in PAN-OS GlobalProtect."}],
       "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
       "references": [{"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "tags": ["Vendor Advisory"]}]}}]}
REC = {"containers": {"cna": {"title": "PAN-OS command injection", "affected": [{"vendor": "Palo Alto Networks", "product": "PAN-OS",
       "versions": [{"version": "11.1", "lessThan": "11.1.2-h3", "status": "affected"}]}],
       "workarounds": [{"lang": "en", "value": "Disable telemetry."}]}}}


def fake_get_json(url, params=None, headers=None, timeout=25):
    if url == data.KEV_URL:
        return {"vulnerabilities": [{"cveID": "CVE-2024-3400", "dueDate": "2024-04-19", "knownRansomwareCampaignUse": "Known"}]}
    if url == data.EPSS_URL:
        return {"data": [{"cve": c, "epss": "0.9", "percentile": "0.99"} for c in params["cve"].split(",")]}
    if url.startswith(data.CVE_RECORD_URL):
        return REC
    if url == data.NVD_URL:
        return NVD if "cveId" in params else NVD
    return None


data._get_json = fake_get_json


def run(**kw):
    data._CACHE.clear()
    ns.reset(**kw)
    sys.modules.pop("app", None)
    importlib.import_module("app")
    return "\n".join(ns.md)


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


# 1) Lookup, arriving from Risk Calc
page = run(query={"cve": "CVE-2024-3400", "priority": "P1", "internet": "yes"})
check("CVE-2024-3400" in page and "pp-brand" in page, "lookup page renders with logo header")
check("🔴 P1" in page and "🔥 In CISA KEV" in page, "priority and KEV badges show")
check("Fix card" in " ".join(str(c) for c in ns.calls), "fix card section rendered")
check("By Div" in page and "linkedin.com/in/divyansh-sharma-8113b5113" in page, "footer with LinkedIn link")
check(any(c[0] == "code" and "CHANGE REQUEST" in str(c[1]) for c in ns.calls), "change request draft generated")
check(any(c[0] == "expander" and "Change request draft" in str(c[1]) for c in ns.calls), "change request sits in a dropdown")
check("Patch download" in page and "login" in page, "download row says a login is needed for Palo Alto")
check(page.count("pp-table pp-compact") >= 3, "fix card, useful links and patch plan are tables")
check("Fixed or first safe versions" not in page and "Pre-checks" in page, "old long lists are gone")

import re  # noqa: E402
css = next(m for m in ns.md if "<style>" in m)
check("max-width: 100% !important" in css and "border-radius: 14px" not in css.split(".pp-suite")[0], "page is full width, no centered box")

# 2) FAQ table
check("<table" in page and "Topic</th><th>Question</th><th>Answer" in page, "FAQ renders as a table")
import patchpilot_content as content  # noqa: E402
check(page.count('class="pp-q"') == len(content.FAQ), f"all {len(content.FAQ)} FAQ rows shown")
page = run(text={"faq_search": "reboot"})
check(0 < page.count('class="pp-q"') < len(content.FAQ), "FAQ search filters rows")

# 3) Bulk bundler
page = run(button=True, text={"bulk_text": "CVE-2024-3400\n91234, Microsoft Windows Security Update (KB5044273)\n777777, ???"})
names = [c[0] for c in ns.calls]
check("Palo Alto Networks PAN-OS" in page and page.count("pp-table-wrap pp-scroll") >= 2, "bundle and detail tables displayed")
dl = [c for c in ns.calls if c[0] == "download_button"]
check(any(isinstance(c[1][1], (bytes, bytearray)) and c[1][1][:2] == b"PK" for c in dl), "Excel patch plan export is a valid xlsx")
check(any("unmapped" in str(c) for c in dl), "unmapped list download offered")
check(any(c[0] == "code" and "Palo Alto" in str(c[1]) for c in ns.calls), "bundle change request drafted")

# 4) KB and keyword paths
page = run(text={"CVE ID, KB number or product keyword": "KB5044273"})
check(any(c[0] == "info" and "KB number" in str(c[1]) for c in ns.calls), "KB lookup path works")
page = run(text={"CVE ID, KB number or product keyword": "PAN-OS GlobalProtect"})
check(any("CVE-2024-3400" in str(c) for c in ns.calls) or "CVE-2024-3400" in page, "keyword lookup path works")

print("\nUI smoke test passed")
