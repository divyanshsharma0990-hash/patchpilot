# PatchPilot

From CVE to change request. Companion to VulnPulse (what's new) and Risk Calc (what's urgent).

By Div: https://www.linkedin.com/in/divyansh-sharma-8113b5113

## What it does
- **Lookup**: CVE, KB number or product keyword. Gives priority (KEV, EPSS, CVSS), then compact tables: fix card (fixed versions, vendor solution, workaround, advisories, patch download), useful links and a platform patch plan. The change request draft sits in a dropdown.
- **Patch download (no login)**: Microsoft Update Catalog links when the KB is known, plus public download pages for a few vendors (Chrome, Firefox, Thunderbird, OpenSSL and others). Vendors that need a support login (Cisco, Palo Alto, Fortinet, F5, Juniper, VMware/Broadcom, Oracle, Citrix) show the advisory instead.
- **Bulk bundler**: paste or upload CVEs, titles or QIDs (no asset or internal data). Groups findings into patch bundles ranked by priority, with Excel/CSV export and a downloadable unmapped list.
- **Playbooks**: checklists for Windows, Linux, VMware ESXi/vCenter, network devices and applications, plus a change request generator.
- **FAQ**: searchable table for patching teams.

## Run locally
```
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
Push this folder to a GitHub repo (keep `bg.jpeg`, `icon.png` and `.streamlit/config.toml` next to `app.py`), then create the app with `app.py` as the main file.

## Link it from VulnPulse and Risk Calc
After deploying, add a button next to each CVE in the other two apps:
```python
PATCHPILOT_URL = "https://YOUR-PATCHPILOT-URL.streamlit.app/"
st.link_button("🛠️ Fix it in PatchPilot", f"{PATCHPILOT_URL}?cve={cve_id}&priority={priority}&internet=yes")
```
PatchPilot reads `cve`, `priority` (P1 to P4) and `internet` (yes/no) from the URL. `internet` is optional.
To open Risk Calc or VulnPulse pre-filled, they need to read `st.query_params.get("cve", "")` themselves.

## Files
| File | Purpose |
|---|---|
| `app.py` | Streamlit UI |
| `patchpilot_core.py` | Priority logic, parsing, bundling, change request text (no network) |
| `patchpilot_data.py` | NVD, CVE.org, CISA KEV and EPSS calls with a one-hour cache |
| `patchpilot_content.py` | Playbooks, path guidance, FAQ text: edit wording here |
| `tests/` | Offline tests: `python tests/test_core.py` and `python tests/smoke_ui.py` |

## Notes
- Priority rules live in `compute_priority()` in `patchpilot_core.py`. Replace that function with your Risk Calc logic to keep both apps aligned.
- Vendor coverage in v1 comes from the CVE record, NVD reference tags and predictable advisory links (Microsoft, Red Hat, Ubuntu, Debian, Palo Alto, Cisco, Fortinet). Authenticated vendor APIs (for example Cisco openVuln) can be added later as adapters.
- The Microsoft KB lookup from a CVE uses the Security Update Guide data, which is not an officially documented API. If it returns nothing, PatchPilot falls back to the Update Catalog home page and the Security Update Guide link.
- NVD limits anonymous requests. A free NVD API key (Settings in the app) raises the limit.
