"""PatchPilot: from CVE to change request.

Companion to VulnPulse (what's new) and Risk Calc (what's urgent).
Run locally with:  streamlit run app.py
"""
from __future__ import annotations

import base64
import datetime as dt
import html
import io
import re
from pathlib import Path

import pandas as pd
import streamlit as st

import patchpilot_content as content
import patchpilot_core as core
import patchpilot_data as data

APP_NAME = "PatchPilot"
VULNPULSE_URL = "https://vulnpulse-intel-app.streamlit.app/"
RISKCALC_URL = "https://div-cve-risk-calc.streamlit.app/"
EOL_RADAR = "https://eol-radar.streamlit.app/"
LINKEDIN_URL = "https://www.linkedin.com/in/divyansh-sharma-8113b5113"
MAX_ROWS = 5000
PRIO_ICON = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}


def load_icon():
    """Use icon.png (shield with a check) as the browser tab icon, fall back to an emoji."""
    p = Path(__file__).parent / "icon.png"
    try:
        from PIL import Image

        return Image.open(p) if p.exists() else "🛠️"
    except Exception:  # noqa: BLE001
        return "🛠️"


st.set_page_config(
    page_title=APP_NAME,
    page_icon=load_icon(),
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ----------------------------------------------------------------------------
# Look and feel
# ----------------------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
html, body, [class*="css"], .stApp { font-family: 'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif; }
.stApp { background-color: #041229; background-image: linear-gradient(rgba(3,10,28,.30), rgba(3,10,28,.50)), __BG__; background-size: cover; background-position: center; background-attachment: fixed; }
[data-testid="stHeader"] { background: transparent; }
.block-container, [data-testid="stMainBlockContainer"] { max-width: 100% !important; margin-top: 0; padding: 1.4rem 3rem 2.5rem !important; background: transparent; border: none; }
@media (max-width: 700px) { .stApp { background-attachment: scroll; } .block-container, [data-testid="stMainBlockContainer"] { padding: 1rem .9rem 1.5rem !important; } }
.pp-suite { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: .9rem; font-size: .85rem; }
.pp-suite a, .pp-suite span { padding: .25rem .7rem; border-radius: 999px; border: 1px solid rgba(120,170,255,.35); color: #b9d4ff !important; text-decoration: none !important; }
.pp-suite a:hover { background: rgba(90,150,255,.18); }
.pp-suite .pp-current { background: #1d6fe0; border-color: #1d6fe0; color: #fff !important; font-weight: 600; }
.pp-hero h1 { margin: 0 0 .2rem 0; padding: 0; font-weight: 700; letter-spacing: -.02em; font-size: 2.3rem; color: #f2f7ff; }
.pp-hero p { margin: 0 0 .6rem 0; color: #a9bddb; font-size: 1.02rem; max-width: 60ch; }
.pp-card { background: rgba(14,36,78,.70); border: 1px solid rgba(110,165,255,.28); border-radius: 10px; padding: 1rem 1.1rem; margin: .4rem 0 .8rem 0; }
.pp-cve { font-size: 1.5rem; font-weight: 700; color: #e9f2ff; margin-bottom: .4rem; }
.pp-card p { margin: .7rem 0 0 0; color: #d3e1f7; line-height: 1.55; }
.pp-badge { display: inline-block; margin: 0 .4rem .3rem 0; padding: .15rem .6rem; border-radius: 6px; font-size: .85rem; font-weight: 600; background: rgba(120,170,255,.16); color: #cfe0ff; border: 1px solid rgba(120,170,255,.30); }
.pp-p1 { background: #c62828; border-color: #c62828; color: #fff; }
.pp-p2 { background: #e65100; border-color: #e65100; color: #fff; }
.pp-p3 { background: #f9a825; border-color: #f9a825; color: #1a1300; }
.pp-p4 { background: #2e7d32; border-color: #2e7d32; color: #fff; }
.pp-kev { background: rgba(255,82,82,.16); border-color: #ff5252; color: #ffb3b3; }
.pp-footer { display: flex; flex-wrap: wrap; align-items: center; gap: .7rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid rgba(110,165,255,.2); color: #b9d4ff; font-size: .9rem; }
.pp-footer a { display: inline-flex; line-height: 0; }
.pp-footer .pp-muted { color: #7f93b3; font-size: .8rem; }
.pp-brand { display: flex; align-items: center; gap: .8rem; margin-bottom: .2rem; }
.pp-brand svg { flex: none; }
.pp-brand h1 { margin: 0 !important; }
.pp-table-wrap { overflow-x: auto; border: 1px solid rgba(110,165,255,.28); border-radius: 10px; margin-top: .6rem; }
.pp-table { width: 100%; min-width: 680px; border-collapse: collapse; font-size: .93rem; }
.pp-table th { text-align: left; padding: .6rem .8rem; background: rgba(29,111,224,.30); color: #eaf3ff; font-weight: 600; border-bottom: 1px solid rgba(110,165,255,.35); }
.pp-table td { padding: .65rem .8rem; vertical-align: top; color: #d3e1f7; line-height: 1.5; border-bottom: 1px solid rgba(110,165,255,.14); }
.pp-table tr:last-child td { border-bottom: none; }
.pp-table tbody tr:nth-child(even) td { background: rgba(14,36,78,.45); }
.pp-table td.pp-q { font-weight: 600; color: #f0f6ff; width: 28%; }
.pp-table td.pp-topic { width: 15%; white-space: nowrap; color: #9fc3ff; }
html { font-size: 17px; }
.stMarkdown p, .stMarkdown li, label p, [data-testid="stCaptionContainer"] { font-size: 1.02rem; }
button[data-baseweb="tab"] p { font-size: 1.1rem; font-weight: 600; }
.stTextInput input, .stTextArea textarea { font-size: 1.05rem; }
.pp-hero h1 { font-size: 2.8rem; }
.pp-hero p { font-size: 1.15rem; max-width: 72ch; }
.pp-suite { font-size: .98rem; }
.pp-cve { font-size: 1.9rem; }
.pp-card p { font-size: 1.08rem; }
.pp-badge { font-size: .98rem; padding: .22rem .7rem; }
.pp-table { font-size: 1.02rem; }
.pp-table th, .pp-table td { padding: .75rem .95rem; }
.pp-scroll { max-height: 560px; overflow: auto; }
.pp-table thead th { position: sticky; top: 0; z-index: 1; }
.pp-table td.pp-num { text-align: right; white-space: nowrap; }
.pp-compact th, .pp-compact td { padding: .5rem .8rem; }
.pp-table td.pp-k { font-weight: 600; color: #f0f6ff; white-space: nowrap; width: 1%; }
.pp-table td ul { margin: 0; padding-left: 1.1rem; }
.pp-table li { margin: .15rem 0; }
.pp-table code { background: rgba(120,170,255,.16); padding: 0 .3rem; border-radius: 4px; font-size: .92em; }
.pp-table a { color: #7fb8ff; }
.pp-note { color: #9fb2cf; font-size: .88rem; }
</style>
"""


@st.cache_resource(show_spinner=False)
def background_css() -> str:
    here = Path(__file__).parent
    for name, mime in (
        ("bg.jpeg", "image/jpeg"),
        ("bg.jpg", "image/jpeg"),
        ("bg.png", "image/png"),
        ("bg.webp", "image/webp"),
    ):
        p = here / name
        if p.exists():
            return f'url("data:{mime};base64,{base64.b64encode(p.read_bytes()).decode()}")'
    return "none"


def badge(text, kind: str = "") -> str:
    cls = f"pp-badge pp-{kind}" if kind else "pp-badge"
    return f'<span class="{cls}">{html.escape(str(text))}</span>'


def md_escape(text: str) -> str:
    return re.sub(r"([\\`*_\[\]()<>#!|~])", r"\\\1", str(text))


def md_link(label: str, url: str) -> str:
    safe = url.replace("(", "%28").replace(")", "%29").replace(" ", "%20")
    return f"[{md_escape(label)}]({safe})"


def render_table(df: pd.DataFrame, max_rows: int = 500) -> None:
    """Show a DataFrame as a large, styled table (same look as the FAQ table)."""
    if df.empty:
        return
    shown = df.head(max_rows)
    head = "".join(f"<th>{html.escape(str(c))}</th>" for c in shown.columns)
    body = []
    for _, row in shown.iterrows():
        cells = []
        for col, v in row.items():
            if v is None or (isinstance(v, float) and v != v):
                text = ""
            elif isinstance(v, float) and v.is_integer():
                text = str(int(v))
            else:
                text = str(v)
            if col == "Priority" and text[:2] in PRIO_ICON:
                cells.append(f"<td>{badge(PRIO_ICON[text[:2]] + ' ' + text, text[:2].lower())}</td>")
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                cells.append(f'<td class="pp-num">{html.escape(text)}</td>')
            else:
                cells.append(f"<td>{html.escape(text)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    st.markdown(
        f'<div class="pp-table-wrap pp-scroll"><table class="pp-table"><thead><tr>{head}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )
    if len(df) > max_rows:
        st.caption(f"Showing the first {max_rows} of {len(df)} rows. The downloads contain everything.")


def esc(s) -> str:
    return html.escape(str(s))


def fmt(s) -> str:
    """Escape text, then turn `code` into <code>."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(str(s)))


def alink(label: str, url: str) -> str:
    return f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener">{esc(label)}</a>'


def ul(items) -> str:
    return "<ul>" + "".join(f"<li>{fmt(i)}</li>" for i in items) + "</ul>"


def ul_html(items_html) -> str:
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items_html) + "</ul>"


def html_table(headers, rows) -> str:
    """Compact two-or-more column table. The first column is the bold key column."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="pp-k">{c}</td>' if i == 0 else f"<td>{c}</td>" for i, c in enumerate(r)) + "</tr>"
        for r in rows
    )
    return f'<div class="pp-table-wrap"><table class="pp-table pp-compact"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def sheet_safe(df: pd.DataFrame) -> pd.DataFrame:
    """Stop spreadsheet apps from treating text as formulas."""

    def fix(v):
        return "'" + v if isinstance(v, str) and v and v[0] in "=+-@" else v

    return df.apply(lambda col: col.map(fix) if col.dtype == object else col)


def render_header() -> None:
    st.markdown(
        f"""<div class="pp-hero">
<div class="pp-suite">
<a href="{VULNPULSE_URL}" target="_blank" rel="noopener">VulnPulse: what's new</a>
<a href="{RISKCALC_URL}" target="_blank" rel="noopener">Risk Calc: what's urgent</a>
<a href="{EOL_RADAR}" target="_blank" rel="noopener">EOL RADAR: If Application EOL?</a>
<span class="pp-current">PatchPilot: how to fix it</span>
</div>
<div class="pp-brand"><svg width="46" height="46" viewBox="0 0 64 64" role="img" aria-label="PatchPilot logo"><defs><linearGradient id="ppg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b8bff"/><stop offset="1" stop-color="#0a3d91"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#ppg)"/><path d="M32 10 L48 16 V30 C48 41 41 49 32 54 C23 49 16 41 16 30 V16 Z" fill="none" stroke="#fff" stroke-width="3" stroke-linejoin="round"/><path d="M24 31 L30 37 L41 25" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg><h1>PatchPilot</h1></div>
<p>Look up a CVE for fix links and a patch plan, or paste a long list and get it grouped into bundles your patching team can work through.</p>
</div>""",
        unsafe_allow_html=True,
    )


def render_footer() -> None:
    st.markdown(
        f"""<div class="pp-footer">
<span>By Div</span>
<a href="{LINKEDIN_URL}" target="_blank" rel="noopener" aria-label="Div on LinkedIn" title="LinkedIn">
<svg width="22" height="22" viewBox="0 0 24 24" role="img" aria-hidden="true"><rect width="24" height="24" rx="4" fill="#0A66C2"/><path fill="#fff" d="M6.94 9.5H4.2V19h2.74V9.5zM5.57 5a1.6 1.6 0 1 0 0 3.2 1.6 1.6 0 0 0 0-3.2zM19.8 13.7c0-2.6-1.4-4.4-3.6-4.4-1.2 0-2 .6-2.4 1.2V9.5h-2.6V19h2.7v-5.1c0-1.3.6-2.2 1.7-2.2s1.5.9 1.5 2.1V19h2.7v-5.3z"/></svg>
</a>
<span class="pp-muted">Data: NVD, CVE.org, CISA KEV, FIRST EPSS. Confirm the fix in the vendor advisory before patching.</span>
</div>""",
        unsafe_allow_html=True,
    )


# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------
def render_settings() -> dict:
    qp = st.query_params
    internet_default = str(qp.get("internet", "")).lower() in ("yes", "true", "1", "y")
    with st.expander("⚙️ Settings: exposure, patch windows, optional NVD key"):
        internet = st.toggle(
            "Mostly internet-facing",
            value=internet_default,
            help="Raises any priority below P1 by one level. Applies to lookups and to bulk bundles.",
        )
        st.caption("Patch window in days for each priority. Set these to match your policy.")
        cols = st.columns(4)
        sla = {
            "P1": cols[0].number_input("P1", min_value=1, value=2, step=1),
            "P2": cols[1].number_input("P2", min_value=1, value=7, step=1),
            "P3": cols[2].number_input("P3", min_value=1, value=30, step=1),
            "P4": cols[3].number_input("P4", min_value=1, value=90, step=1),
        }
        nvd_key = st.text_input(
            "NVD API key (optional)",
            type="password",
            help="A free key from nvd.nist.gov raises the NVD rate limit. It is only used for your session.",
        )
    return {"internet": internet, "sla": sla, "nvd_key": nvd_key.strip()}


# ----------------------------------------------------------------------------
# Playbooks
# ----------------------------------------------------------------------------
def render_playbook(platform: str, path: str) -> None:
    wf = content.WORKFLOWS[platform]
    rows = [
        (f"{path} change", ul(content.PATH_NOTES[path])),
        ("Pre-checks", ul(wf["pre"])),
        ("Patch", ul(wf["patch"])),
        ("Validate", ul(wf["validate"])),
        ("Roll back", ul(wf["rollback"])),
    ]
    st.markdown(html_table(["Stage", "What to do"], rows), unsafe_allow_html=True)


def fix_target_text(fixed_pairs) -> str:
    seen, out = set(), []
    for product, ver in fixed_pairs:
        item = f"{product} {ver}".strip()
        if item not in seen:
            seen.add(item)
            out.append(item)
    return "; ".join(out[:5]) + (f" (+{len(out) - 5} more)" if len(out) > 5 else "")


# ----------------------------------------------------------------------------
# Lookup tab
# ----------------------------------------------------------------------------
def render_cve(cve_id: str, s: dict) -> None:
    with st.spinner(f"Fetching {cve_id}..."):
        nvd = core.parse_nvd(data.get_nvd_cve(cve_id, s["nvd_key"]))
        rec = core.parse_cve_record(data.get_cve_record(cve_id))
        kev = data.get_kev().get(cve_id)
        epss = data.get_epss([cve_id]).get(cve_id) or {}

    if not nvd and not (rec["vendor"] or rec["product"] or rec["title"] or rec["fixed"]) and not kev:
        st.error(
            f"No data found for {cve_id}. Check the ID. If it is valid, the public sources may be busy "
            "(NVD limits requests): try again in a minute or add a free NVD API key in Settings."
        )
        return

    cvss = (nvd or {}).get("cvss") or rec["cvss"]
    desc = (nvd or {}).get("description") or rec["title"] or "No description available."
    epss_val = epss.get("epss")
    prio = core.compute_priority(bool(kev), epss_val, cvss, s["internet"])

    qp = st.query_params
    from_rc = str(qp.get("priority", "")).upper()
    rc_note = ""
    if str(qp.get("cve", "")).upper() == cve_id and from_rc in ("P1", "P2", "P3", "P4"):
        prio = from_rc
        rc_note = "Priority carried over from Risk Calc."

    badges = badge(f"{PRIO_ICON[prio]} {prio}", prio.lower())
    if kev:
        badges += badge("🔥 In CISA KEV", "kev")
    if cvss:
        badges += badge(f"CVSS {cvss:.1f}")
    if epss_val is not None:
        badges += badge(f"EPSS {epss_val * 100:.1f}%")
    st.markdown(
        f'<div class="pp-card"><div class="pp-cve">{html.escape(cve_id)}</div>'
        f"<div>{badges}</div><p>{html.escape(desc)}</p></div>",
        unsafe_allow_html=True,
    )

    due = dt.date.today() + dt.timedelta(days=int(s["sla"][prio]))
    facts = [f"Suggested patch date: {due:%d %b %Y} ({prio} window, {int(s['sla'][prio])} days)"]
    if kev:
        if kev.get("dueDate"):
            facts.append(f"CISA KEV due date: {kev['dueDate']}")
        if str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known":
            facts.append("Known to be used in ransomware campaigns")
    if rec["vendor"] or rec["product"]:
        facts.append(f"Affected: {rec['vendor']} {rec['product']}".strip())
    if nvd and nvd.get("published"):
        facts.append(f"Published {nvd['published']}")
    if rc_note:
        facts.append(rc_note)
    st.caption("  \n".join(facts))

    with st.expander("💡 Why this priority"):
        reasons = core.priority_reasons(bool(kev), epss_val, cvss, s["internet"])
        st.markdown("\n".join(f"- {r}" for r in reasons) or "- No scoring data was available.")

    # ---- Fix card and useful links, side by side
    refs = (nvd or {}).get("references", []) + rec["references"]
    fix_refs, _other = core.classify_references(refs)
    platform_auto = core.detect_platform(rec["vendor"], rec["product"], desc)
    kbs = core.extract_kbs(" ".join(r.get("url", "") for r in refs), " ".join(rec["solutions"]), desc)
    if not kbs and platform_auto == "Windows":
        with st.spinner("Checking Microsoft update data..."):
            kbs = data.get_msrc_kbs(cve_id)
    dl_text = f"{rec['vendor']} {rec['product']}".strip() or desc
    downloads = core.download_options(platform_auto, dl_text, kbs)

    rows = []
    if not (rec["fixed"] or rec["fixed_other"] or rec["solutions"] or rec["workarounds"] or fix_refs):
        rows.append((
            "Fix data",
            esc("No structured fix data was found for this CVE. Use the links and confirm the fixed version in the vendor advisory."),
        ))
    if rec["fixed"]:
        rows.append(("Fixed versions", ul([f"{p_}: {v}" if p_ else v for p_, v in rec["fixed"][:8]])))
    if rec["fixed_other"]:
        names = [v if len(v) <= 40 else v[:12] + "..." for _, v in rec["fixed_other"][:3]]
        more = len(rec["fixed_other"]) - 3
        rows.append(("Other fixes", fmt("; ".join(names) + (f" (+{more} more in the CVE record)" if more > 0 else ""))))
    if rec["solutions"]:
        rows.append(("Vendor solution", ul([t[:300] for t in rec["solutions"][:2]])))
    if rec["workarounds"]:
        rows.append(("Workaround", ul([t[:300] for t in rec["workarounds"][:2]])))
    if fix_refs:
        items = []
        for r in fix_refs[:6]:
            tag = f" ({', '.join(r['tags'])})" if r["tags"] else ""
            items.append(alink(r["vendor"] or r["host"], r["url"]) + esc(tag))
        rows.append(("Advisories", ul_html(items)))
    dl_items = []
    for o in downloads:
        head = alink(o["label"], o["url"]) if o["url"] else f"<b>{esc(o['label'])}</b>"
        dl_items.append(f'{head} <span class="pp-note">{esc(o["note"])}</span>')
    rows.append(("Patch download", ul_html(dl_items)))

    links = core.vendor_links(cve_id, platform_auto, f"{rec['vendor']} {rec['product']}")
    left, right = st.columns([3, 2])
    with left:
        st.subheader("🩹 Fix card")
        st.markdown(html_table(["Item", "Details"], rows), unsafe_allow_html=True)
    with right:
        st.subheader("🔗 Useful links")
        st.markdown(
            html_table(["Where", "Link"], [(esc(n), alink("Open", u)) for n, u in links]),
            unsafe_allow_html=True,
        )

    # ---- Patch plan table
    st.subheader("🗺️ Patch plan")
    c1, c2 = st.columns(2)
    platform = c1.selectbox(
        "Platform",
        content.PLATFORMS,
        index=content.PLATFORMS.index(platform_auto),
        key=f"plat_{cve_id}",
    )
    path = c2.radio(
        "Change path",
        ["Emergency", "Normal"],
        index=0 if core.path_for_priority(prio) == "Emergency" else 1,
        horizontal=True,
        key=f"path_{cve_id}_{prio}",
    )
    render_playbook(platform, path)

    # ---- Change request in a dropdown
    title = f"Patch {cve_id}" + (f" ({rec['vendor']} {rec['product']})".replace("( ", "(") if rec["vendor"] or rec["product"] else "")
    text = core.change_request_text(
        title=title,
        cves=[cve_id],
        priority=prio,
        platform=platform,
        path=path,
        fix_target=fix_target_text(rec["fixed"]),
        kev_count=1 if kev else 0,
        links=links[:4],
        sla_days=int(s["sla"][prio]),
    )
    with st.expander("📝 Change request draft"):
        st.code(text, language=None)
        st.download_button("⬇️ Download as text file", text, file_name=f"change-request-{cve_id}.txt", key=f"dl_{cve_id}")

    b1, b2, _ = st.columns([2, 2, 3])
    b1.link_button("🎯 Score it in Risk Calc", f"{RISKCALC_URL}?cve={cve_id}")
    b2.link_button("📡 See related news in VulnPulse", VULNPULSE_URL)


def render_kb(kb: str) -> None:
    st.subheader(f"KB{kb}")
    st.markdown("\n".join(f"- {md_link(n, u)}" for n, u in core.kb_links(kb)))
    st.info(
        "A KB number cannot be mapped to CVEs with public data here. Open the support article for the "
        "CVE list and any known issues, then look up the CVEs you care about, or paste them into the Bulk bundler."
    )


def render_keyword(q: str, s: dict) -> None:
    with st.spinner("Searching NVD..."):
        items = core.parse_nvd_list(data.search_nvd(q, s["nvd_key"]))
    if not items:
        st.warning(
            "No CVEs found for that keyword, or NVD did not answer. Try the vendor and product name "
            "(for example 'Fortinet FortiOS') or a CVE ID."
        )
        return
    labels = {i["id"]: f"{i['id']} (CVSS {i['cvss'] or 'n/a'}): {i['description'][:90]}" for i in items}
    pick = st.selectbox(
        "First 20 NVD matches (add a version or component to narrow the search)",
        list(labels),
        format_func=lambda k: labels[k],
    )
    render_cve(pick, s)


def render_lookup(s: dict) -> None:
    default = str(st.query_params.get("cve", ""))
    with st.form("lookup_form"):
        q = st.text_input(
            "CVE ID, KB number or product keyword",
            value=default,
            placeholder="CVE-2024-3400, KB5044273 or PAN-OS GlobalProtect",
        )
        st.form_submit_button("🔎 Look up", type="primary")
    q = q.strip()
    if not q:
        st.info("Enter a CVE ID to get fix links, a priority and a patch plan.")
        return
    cves = core.CVE_RE.findall(q)
    if cves:
        render_cve(cves[0].upper(), s)
        return
    kb = core.KB_RE.search(q)
    if kb:
        render_kb(kb.group(1))
        return
    if len(q) < 3:
        st.warning("Type at least 3 characters.")
        return
    render_keyword(q, s)


# ----------------------------------------------------------------------------
# Bulk bundler tab
# ----------------------------------------------------------------------------
def read_upload(file):
    name = file.name.lower()
    try:
        if name.endswith(".xlsx"):
            df = pd.read_excel(file, dtype=str)
        else:
            df = pd.read_csv(file, dtype=str, keep_default_na=False, encoding_errors="replace", on_bad_lines="skip")
    except Exception as exc:  # noqa: BLE001
        return [], f"Could not read {file.name}: {exc}"
    rows = core.rows_from_records(df.to_dict("records"), list(df.columns))
    if not rows:
        return [], f"No CVE, title or QID values found in {file.name}. The first row must be a header such as CVE, Title, QID."
    return rows, ""


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return sheet_safe(df).to_csv(index=False).encode("utf-8")


def render_bulk(s: dict) -> None:
    st.markdown(
        "Paste findings (one per line) or upload a CSV or Excel file with columns such as **CVE**, **Title** and **QID**. "
        "Use only these fields. Please leave out hostnames, IP addresses and other internal data."
    )
    up = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"], key="bulk_file")
    text = st.text_area(
        "Or paste here",
        height=150,
        key="bulk_text",
        placeholder="CVE-2024-3400\n91234, Microsoft Windows Security Update for October 2026 (KB5044273)\nCVE-2023-4966",
    )
    deep = st.slider(
        "Product lookups for CVE-only rows (riskiest first)",
        0,
        500,
        150,
        25,
        help="Fetches product, CVSS and fixed versions from the CVE record. More lookups give better bundles but take longer.",
    )

    if st.button("📦 Build bundles", type="primary"):
        rows, errors = [], []
        if up is not None:
            r, err = read_upload(up)
            rows += r
            if err:
                errors.append(err)
        if text.strip():
            rows += core.parse_bulk_text(text)
        for e in errors:
            st.error(e)
        if not rows:
            st.warning("Nothing to process yet. Paste some findings or upload a file.")
        else:
            if len(rows) > MAX_ROWS:
                st.warning(f"Only the first {MAX_ROWS} findings were processed.")
                rows = rows[:MAX_ROWS]
            cves = sorted({r["cve"] for r in rows if r["cve"]})
            enrich = {}
            if cves:
                prog = st.progress(0.0, text="Fetching exploitation data (CISA KEV and EPSS)...")
                enrich = data.enrich_cves(
                    cves,
                    deep,
                    progress=lambda f: prog.progress(min(f, 1.0), text=f"Looking up CVE details: {int(f * 100)}%"),
                )
                prog.empty()
                if not any(v["epss"] is not None or v["kev"] for v in enrich.values()):
                    st.warning(
                        "Exploitation data (EPSS and KEV) could not be fetched, so priorities below are unreliable. "
                        "Try again in a minute."
                    )
            bundles, cve_rows, unmapped = core.build_bundles(rows, enrich, s["internet"])
            st.session_state["bulk"] = {
                "bundles": bundles,
                "cve_rows": cve_rows,
                "unmapped": unmapped,
                "findings": len(rows),
                "cves": len(cves),
                "internet": s["internet"],
            }

    res = st.session_state.get("bulk")
    if res:
        render_bulk_results(res, s)


BUNDLE_COLS = [
    "ID", "Bundle", "Platform", "Priority", "Wave", "CVEs", "KEV", "Max EPSS %",
    "Max CVSS", "Fix target", "Fix notes", "Reboot", "Unscored", "Findings",
]


def render_bulk_results(res: dict, s: dict) -> None:
    bundles, cve_rows, unmapped = res["bundles"], res["cve_rows"], res["unmapped"]
    st.divider()
    if res["internet"] != s["internet"]:
        st.info("The exposure setting changed since these bundles were built. Press Build bundles to refresh them.")

    m = st.columns(4)
    m[0].metric("Findings", res["findings"])
    m[1].metric("Unique CVEs", res["cves"])
    m[2].metric("Bundles", len(bundles))
    m[3].metric("In CISA KEV", sum(b["KEV"] for b in bundles))

    if not bundles and not unmapped:
        st.warning("No bundles could be built from this input.")
        return

    if bundles:
        df = pd.DataFrame([{k: b[k] for k in BUNDLE_COLS} for b in bundles])
        st.subheader("📦 Bundles in patching order")
        st.caption(
            "Ranked by highest priority, then KEV count, then CVEs closed. "
            "Fix target is the highest fixed version listed in the CVE records; older release branches can have lower "
            "fixed versions, so confirm in the vendor advisory. Unscored rows had a title but no CVE and count as P3."
        )
        render_table(df)

        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as xw:
            sheet_safe(df).to_excel(xw, sheet_name="Bundles", index=False)
            sheet_safe(pd.DataFrame(cve_rows)).to_excel(xw, sheet_name="Findings by bundle", index=False)
            if unmapped:
                sheet_safe(pd.DataFrame(unmapped)).to_excel(xw, sheet_name="Unmapped", index=False)
        d1, d2 = st.columns(2)
        d1.download_button(
            "⬇️ Download patch plan (Excel)",
            buf.getvalue(),
            file_name="patchpilot-bundles.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        d2.download_button("⬇️ Download bundles (CSV)", to_csv_bytes(df), file_name="patchpilot-bundles.csv", mime="text/csv")

        st.subheader("🔍 Bundle details")
        labels = {b["ID"]: f"{b['ID']}: {b['Bundle']} ({b['Priority']}, {b['CVEs']} CVEs)" for b in bundles}
        pick = st.selectbox("Choose a bundle", list(labels), format_func=lambda k: labels[k], key="bulk_pick")
        b = next(x for x in bundles if x["ID"] == pick)
        rows_df = pd.DataFrame([r for r in cve_rows if r["Bundle"] == b["Bundle"]]).drop(columns=["Bundle"])
        render_table(rows_df)

        if b["Bundle"].startswith("Microsoft KB"):
            st.markdown("**Patch download (no sign-in):** " + " | ".join(md_link(n, u) for n, u in core.kb_links(b["Bundle"])))
        platform_default = b["Platform"] if b["Platform"] in content.PLATFORMS else "Application / other"
        c1, c2 = st.columns(2)
        platform = c1.selectbox(
            "Platform", content.PLATFORMS, index=content.PLATFORMS.index(platform_default), key=f"bplat_{pick}"
        )
        path = c2.radio(
            "Change path",
            ["Emergency", "Normal"],
            index=0 if core.path_for_priority(b["Priority"]) == "Emergency" else 1,
            horizontal=True,
            key=f"bpath_{pick}",
        )
        with st.expander("Checklist for this bundle"):
            render_playbook(platform, path)
        text = core.change_request_text(
            title=f"Patch bundle: {b['Bundle']}",
            cves=b["_cves"],
            priority=b["Priority"],
            platform=platform,
            path=path,
            fix_target=b["Fix target"],
            kev_count=b["KEV"],
            sla_days=int(s["sla"][b["Priority"]]),
        )
        with st.expander("📝 Change request draft"):
            st.code(text, language=None)
            st.download_button("⬇️ Download as text file", text, file_name=f"change-request-{pick}.txt", key=f"bdl_{pick}")

    if unmapped:
        st.subheader("🧩 Unmapped findings")
        st.warning(
            f"{len(unmapped)} finding(s) had no CVE and no product PatchPilot could recognise. "
            "Download the list, fill in the CVE column, and upload it again."
        )
        udf = pd.DataFrame(unmapped)
        render_table(udf)
        st.download_button(
            "⬇️ Download unmapped list (CSV)", to_csv_bytes(udf), file_name="patchpilot-unmapped.csv", mime="text/csv"
        )


# ----------------------------------------------------------------------------
# Playbooks tab and FAQ tab
# ----------------------------------------------------------------------------
def render_playbooks(s: dict) -> None:
    st.markdown("Checklists for each platform, plus a change request generator you can fill in by hand.")
    c1, c2 = st.columns(2)
    platform = c1.selectbox("Platform", content.PLATFORMS, key="pb_plat")
    path = c2.radio("Change path", ["Emergency", "Normal"], index=1, horizontal=True, key="pb_path")
    render_playbook(platform, path)

    st.subheader("📝 Change request generator")
    with st.form("cr_form"):
        title = st.text_input("Title", placeholder="Patch Palo Alto firewalls for CVE-2024-3400")
        cves_text = st.text_area("CVE IDs (optional)", height=80)
        f1, f2 = st.columns(2)
        prio = f1.selectbox("Priority", ["P1", "P2", "P3", "P4"], index=1)
        plat = f2.selectbox("Platform", content.PLATFORMS, key="cr_plat")
        fix = st.text_input("Fix or target version (optional)")
        go = st.form_submit_button("📝 Generate", type="primary")
    if go:
        cves = list(dict.fromkeys(c.upper() for c in core.CVE_RE.findall(cves_text)))
        text = core.change_request_text(
            title=title.strip() or "Security patch",
            cves=cves,
            priority=prio,
            platform=plat,
            path=core.path_for_priority(prio),
            fix_target=fix.strip(),
            sla_days=int(s["sla"][prio]),
        )
        st.code(text, language=None)
        st.download_button("⬇️ Download as text file", text, file_name="change-request.txt", key="cr_dl")


def render_faq() -> None:
    st.caption("General best practice for patching teams. Adjust to your organization's policy and the vendor's guidance.")
    topics = list(dict.fromkeys(t for t, _, _ in content.FAQ))
    c1, c2 = st.columns([2, 1])
    term = c1.text_input("Search the FAQ", placeholder="reboot, rollback, KEV, QID...", key="faq_search").strip().lower()
    topic = c2.selectbox("Topic", ["All topics"] + topics, key="faq_topic")
    rows = [
        (t, q, a)
        for t, q, a in content.FAQ
        if (topic == "All topics" or t == topic) and (not term or term in f"{t} {q} {a}".lower())
    ]
    if not rows:
        st.info("No FAQ entries match. Clear the search or choose All topics.")
        return
    body = "".join(
        f'<tr><td class="pp-topic">{html.escape(t)}</td><td class="pp-q">{html.escape(q)}</td><td>{html.escape(a)}</td></tr>'
        for t, q, a in rows
    )
    st.markdown(
        '<div class="pp-table-wrap"><table class="pp-table"><thead><tr><th>Topic</th><th>Question</th><th>Answer</th></tr></thead>'
        f"<tbody>{body}</tbody></table></div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Showing {len(rows)} of {len(content.FAQ)} entries.")


# ----------------------------------------------------------------------------
def main() -> None:
    st.markdown(CSS.replace("__BG__", background_css()), unsafe_allow_html=True)
    render_header()
    s = render_settings()
    tabs = st.tabs(["🔎 Lookup", "📦 Bulk bundler", "🧭 Playbooks", "❓ FAQ"])
    with tabs[0]:
        render_lookup(s)
    with tabs[1]:
        render_bulk(s)
    with tabs[2]:
        render_playbooks(s)
    with tabs[3]:
        render_faq()
    render_footer()


main()
