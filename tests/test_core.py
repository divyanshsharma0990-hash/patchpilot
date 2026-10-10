"""Offline tests: no network needed. Run with:  python tests/test_core.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import patchpilot_core as core
import patchpilot_data as data


def test_priority():
    assert core.compute_priority(True, 0.01, 5.0) == "P1"
    assert core.compute_priority(False, 0.80, 5.0) == "P1"
    assert core.compute_priority(False, 0.05, 9.8) == "P2"
    assert core.compute_priority(False, 0.12, 5.0) == "P3"
    assert core.compute_priority(False, 0.01, 4.0) == "P4"
    assert core.compute_priority(False, 0.01, 4.0, internet_facing=True) == "P3"
    assert core.compute_priority(True, None, None, internet_facing=True) == "P1"
    assert core.path_for_priority("P1") == "Emergency" and core.path_for_priority("P3") == "Normal"


def test_parse_nvd():
    raw = {"vulnerabilities": [{"cve": {
        "id": "CVE-2024-0001", "published": "2024-01-02T00:00:00", "lastModified": "2024-02-03T00:00:00",
        "descriptions": [{"lang": "en", "value": "Bad <b>bug</b> &amp; worse"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "X"}}]},
        "references": [{"url": "https://security.paloaltonetworks.com/CVE-2024-0001", "tags": ["Vendor Advisory"]},
                       {"url": "javascript:alert(1)", "tags": ["Patch"]},
                       {"url": "https://example.org/blog", "tags": []}]}}]}
    p = core.parse_nvd(raw)
    assert p["cvss"] == 9.8 and p["published"] == "2024-01-02" and "bug" in p["description"] and "<b>" not in p["description"]
    fix, other = core.classify_references(p["references"])
    assert len(fix) == 1 and fix[0]["vendor"] == "Palo Alto Networks"      # javascript: link is dropped
    assert len(other) == 1
    assert core.parse_nvd({}) is None and core.parse_nvd({"vulnerabilities": []}) is None


def test_parse_record():
    rec = {"containers": {
        "cna": {"title": "PAN-OS issue",
                "affected": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "versions": [
                    {"version": "10.2", "lessThan": "10.2.9-h1", "status": "affected"},
                    {"version": "11.0", "status": "affected", "lessThan": "11.0.4-h1"},
                    {"version": "11.1.2", "status": "unaffected"}]}],
                "solutions": [{"lang": "en", "value": "<p>Upgrade to <b>10.2.9-h1</b></p>"}],
                "workarounds": [{"lang": "en", "value": "Disable telemetry"}],
                "references": [{"url": "https://security.paloaltonetworks.com/CVE-X", "tags": ["vendor-advisory"]}]},
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 10.0}}]}]}}
    r = core.parse_record = core.parse_cve_record(rec)
    assert r["vendor"] == "Palo Alto Networks" and r["product"] == "PAN-OS"
    assert ("PAN-OS", "10.2.9-h1") in r["fixed"] and ("PAN-OS", "11.1.2") in r["fixed"]
    assert r["solutions"] == ["Upgrade to 10.2.9-h1"] and r["workarounds"] == ["Disable telemetry"]
    assert r["cvss"] == 10.0
    assert core.max_version([v for _, v in r["fixed"]]) == "11.1.2"
    fix, _ = core.classify_references(r["references"])
    assert len(fix) == 1                                                   # "vendor-advisory" tag normalised
    assert core.parse_cve_record(None)["fixed"] == []


def test_version_filter():
    for good in ("10.2.9-h1", "24.2", "161.20", "53.0.8010.36", "0.0.28000.2954", "6.0.5", "9.3.1021", "v2.1.3", "11.1.2-h3"):
        assert core.is_version(good), good
    for bad in ("18675263db1147cabc1234567890abcdef12345", "deadbeef1234", "Hotfix-BIGIP-21.1.0.0.54.1-ENG",
                "Hotfix for CVE-2024-1234", "", "2024", "x" * 60):
        assert not core.is_version(bad), bad
    rec = {"containers": {"cna": {"affected": [{"vendor": "Linux", "product": "Linux", "versions": [
        {"version": "5.10.200", "status": "unaffected"},
        {"version": "18675263db1147cabc1234567890abcdef12345", "status": "unaffected"},
        {"version": "0", "lessThan": "6.1.60", "status": "affected"},
        {"version": "1.0", "lessThan": "Hotfix-BIGIP-21.1.0.0.54.1-ENG", "status": "affected"}]}]}}}
    r = core.parse_cve_record(rec)
    assert [v for _, v in r["fixed"]] == ["5.10.200", "6.1.60"]
    assert len(r["fixed_other"]) == 2 and core.max_version([v for _, v in r["fixed"]]) == "6.1.60"
    bundles, _, _ = core.build_bundles(
        [{"cve": "CVE-2024-1", "title": "", "qid": ""}],
        {"CVE-2024-1": {"kev": False, "epss": 0.01, "cvss": 5.0, "vendor": "Linux", "product": "Linux",
                        "fixed": r["fixed"], "fixed_other": r["fixed_other"]}})
    assert bundles[0]["Fix target"] == "6.1.60" and "2 hotfix/commit" in bundles[0]["Fix notes"]


def test_downloads():
    assert core.extract_kbs("fix in KB5044273", "https://support.microsoft.com/help/5044284", "kb5044273 again") == ["5044273", "5044284"]
    ms = core.download_options("Windows", "microsoft windows", ["5044273"])
    assert ms[0]["url"].endswith("q=KB5044273") and "No sign-in" in ms[0]["note"]
    assert core.download_options("Windows", "microsoft windows", [])[0]["url"] == "https://www.catalog.update.microsoft.com/"
    chrome = core.download_options("Application / other", "google chrome")
    assert chrome[0]["url"] == "https://www.google.com/chrome/"
    for text, plat in (("palo alto pan-os", "Network device"), ("vmware esxi", "VMware ESXi / vCenter"), ("cisco ios xe", "Network device")):
        o = core.download_options(plat, text)
        assert o[-1]["url"] == "" and "login" in o[-1]["note"], text          # honest: no public file
    assert core.download_options("Application / other", "acme widget")[0]["url"] == ""
    assert all(o["url"].startswith("https://") for t in ("firefox", "openssl", "7-zip", "wireshark")
               for o in core.download_options("Application / other", t) if o["url"])


def test_msrc_kb_parser():
    def fake(url, params=None, headers=None, timeout=25):
        return {"value": [{"kbArticles": [{"articleName": "5044273", "downloadUrl": "https://x/12345678-aaaa"},
                                          {"articleName": "KB5044284"}, {"articleName": "not a kb"}]}]}
    old = data._get_json
    data._CACHE.clear(); data._get_json = fake
    try:
        assert data.get_msrc_kbs("CVE-2024-38063") == ["5044273", "5044284"]
        data._get_json = lambda *a, **k: None
        data._CACHE.clear()
        assert data.get_msrc_kbs("CVE-2024-38063") == []                     # failure is harmless
    finally:
        data._get_json = old


def test_platform_and_titles():
    assert core.detect_platform("VMware", "ESXi") == "VMware ESXi / vCenter"
    assert core.detect_platform("Cisco", "IOS XE") == "Network device"
    assert core.detect_platform("Microsoft", "Windows 11") == "Windows"
    assert core.detect_platform("Linux", "Linux") == "Linux"
    assert core.detect_platform("Acme", "Widget") == "Application / other"
    assert core.bundle_key("Microsoft Windows Security Update (KB5044273)", {}) == ("Microsoft KB5044273", "Windows")
    assert core.bundle_key("Microsoft Windows Security Update for October 2026", {})[0] == "Microsoft Windows (October 2026)"
    assert core.bundle_key("Palo Alto PAN-OS GlobalProtect RCE", {})[1] == "Network device"
    assert core.bundle_key("", {}) == (None, None)
    assert core.product_label("Microsoft", "Windows 11 23H2") == "Microsoft Windows"
    assert core.product_label("Palo Alto Networks", "PAN-OS") == "Palo Alto Networks PAN-OS"


def test_bulk_parsing():
    rows = core.parse_bulk_text(
        "CVE-2024-3400\n91234, Microsoft Windows Security Update for October 2026 (KB5044273)\n"
        "55555 Some Unknown Thing\nCVE-2023-4966, CVE-2023-1111 Citrix\n\n")
    assert rows[0] == {"cve": "CVE-2024-3400", "title": "", "qid": ""}
    assert rows[1]["qid"] == "91234" and "KB5044273" in rows[1]["title"] and rows[1]["cve"] == ""
    assert rows[2]["qid"] == "55555" and rows[2]["title"] == "Some Unknown Thing"
    assert {r["cve"] for r in rows[3:]} == {"CVE-2023-4966", "CVE-2023-1111"}

    import pandas as pd
    df = pd.DataFrame({"QID": [91234.0, None], "Title": ["Cisco IOS XE bug", "Mystery"], "CVE ID": ["CVE-2023-20198, CVE-2023-20273", ""]})
    rows = core.rows_from_records(df.to_dict("records"), list(df.columns))
    assert [r["cve"] for r in rows] == ["CVE-2023-20198", "CVE-2023-20273", ""]
    assert rows[0]["qid"] == "91234"
    nohead = core.rows_from_records([{"a": "see CVE-2022-0001 here"}], ["a"])
    assert nohead[0]["cve"] == "CVE-2022-0001"


def test_bundles():
    rows = core.parse_bulk_text(
        "CVE-2024-3400\nCVE-2024-9999\nCVE-2023-4966\n"
        "91234, Microsoft Windows Security Update (KB5044273)\n"
        "777777, ???\nCVE-2024-3400\n")
    enrich = {
        "CVE-2024-3400": {"kev": True, "epss": 0.95, "cvss": 10.0, "vendor": "Palo Alto Networks", "product": "PAN-OS",
                          "fixed": [("PAN-OS", "10.2.9-h1"), ("PAN-OS", "11.1.2")]},
        "CVE-2024-9999": {"kev": False, "epss": 0.02, "cvss": 7.5, "vendor": "Palo Alto Networks", "product": "PAN-OS", "fixed": []},
        "CVE-2023-4966": {"kev": True, "epss": 0.9, "cvss": 9.4, "vendor": "Citrix", "product": "NetScaler ADC", "fixed": []},
    }
    bundles, cve_rows, unmapped = core.build_bundles(rows, enrich)
    names = [b["Bundle"] for b in bundles]
    assert "Palo Alto Networks PAN-OS" in names and "Microsoft KB5044273" in names
    pan = next(b for b in bundles if b["Bundle"] == "Palo Alto Networks PAN-OS")
    assert pan["CVEs"] == 2 and pan["KEV"] == 1 and pan["Priority"] == "P1" and pan["Fix target"] == "11.1.2"
    assert pan["Wave"] == "Emergency" and pan["Platform"] == "Network device"
    kb = next(b for b in bundles if b["Bundle"] == "Microsoft KB5044273")
    assert kb["Priority"] == "P3" and kb["Unscored"] == 1
    assert unmapped == [{"QID": "777777", "Title": "???", "CVE": ""}]
    assert [b["ID"] for b in bundles] == ["B01", "B02", "B03"]            # ranked and numbered
    assert bundles[0]["Priority"] == "P1"
    assert sum(1 for r in cve_rows if r["CVE"] == "CVE-2024-3400") == 1   # duplicate row removed


def test_change_request():
    t = core.change_request_text(title="Patch X", cves=["CVE-2024-3400"], priority="P1", platform="Network device",
                                 path="Emergency", fix_target="11.1.2", kev_count=1, sla_days=2,
                                 links=[("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2024-3400")])
    for needle in ("Emergency", "CVE-2024-3400", "11.1.2", "Rollback plan", "Known Exploited", "NVD", "[change owner to complete]"):
        assert needle in t, needle


def test_links():
    names = [n for n, _ in core.vendor_links("cve-2024-3400", "Network device", "Palo Alto Networks PAN-OS")]
    assert "Palo Alto Networks advisory" in names and "NVD entry" in names
    assert all(u.startswith("https://") for _, u in core.vendor_links("CVE-2024-1", "Linux", ""))
    assert core.kb_links("KB5044273")[0][1].endswith("KB5044273")


def test_data_layer_with_fake_network():
    calls = []

    def fake_get_json(url, params=None, headers=None, timeout=25):
        calls.append(url)
        if url == data.KEV_URL:
            return {"vulnerabilities": [{"cveID": "CVE-2024-3400", "dueDate": "2024-04-19", "knownRansomwareCampaignUse": "Unknown"}]}
        if url == data.EPSS_URL:
            return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in params["cve"].split(",")]}
        if url.startswith(data.CVE_RECORD_URL):
            return {"containers": {"cna": {"affected": [{"vendor": "V", "product": "P", "versions": [{"version": "2.0", "status": "unaffected"}]}]}}}
        return None

    data._CACHE.clear()
    data._get_json = fake_get_json
    seen = []
    info = data.enrich_cves(["CVE-2024-3400", "CVE-2020-0001", "CVE-2020-0002"], max_deep=2, progress=seen.append)
    assert info["CVE-2024-3400"]["kev"] and info["CVE-2024-3400"]["kev_due"] == "2024-04-19"
    assert info["CVE-2020-0001"]["epss"] == 0.5
    deep = [c for c, v in info.items() if v["vendor"]]
    assert len(deep) == 2 and "CVE-2024-3400" in deep                      # riskiest looked up first, capped at 2
    assert seen and seen[-1] == 1.0
    n = len(calls)
    data.enrich_cves(["CVE-2024-3400"], max_deep=1)
    assert len(calls) == n                                                  # second run served from cache


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"\nAll {len(tests)} tests passed")
