"""Record a captioned video tour of the demo report (for partners who will not run code).

    pip install playwright && playwright install chromium     # plus ffmpeg on the PATH
    python examples/insurance_onboarding/demo.py --html        # in an empty folder
    python examples/insurance_onboarding/record_video.py       # writes .dpdp/demo-tour.mp4

Options: --report PATH, --output PATH, --chrome PATH (use an installed Chrome), --width/--height.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

INTRO = ("DPDP Data Rights Framework for AI Agents",
         "An insurance onboarding demo. Four applicants talk to an AI agent; then they use their rights "
         "under India's DPDP Act. Everything runs offline; all people are fictional.")
CAPTIONS = [
    "Personal data is replaced with tokens before any log, index, cache or memory stores it. "
    "Each person has their own encryption key.",
    "Consent is recorded per person and per purpose, not once per customer.",
    "Anita withdraws marketing consent only. Her audience entry is deleted; her application continues.",
    "Lineage: everything Priya's data turned into, including a cache row the code never registered. "
    "Discovery found it anyway.",
    "Priya asks to be erased. One decision per item, with the reason: delete, redact where she is only mentioned, "
    "rebuild the report, keep KYC under a legal hold.",
    "After the erasure: Rahul's application keeps everything except Priya's email, which now reads [ERASED].",
    "Verification re-checks every store. A signed, hash-chained certificate records every action and exception.",
    "A person handles a system with no connector; an independent reviewer signs the case off. "
    "The evidence bundle and audit pack verify offline.",
    "The other rights: Rahul's access report, a correction applied once in the vault, a nomination, "
    "and Anita's grievance resolved within its period.",
]
ACCESS = "What Rahul receives for an access request: what is held, where, why, and who it was shared with."
OUTRO = ("Run it yourself in one minute",
         "python examples/insurance_onboarding/demo.py --html\n"
         "github.com/koushikmohanbhat/dpdp-data-rights-framework")

OVERLAY_JS = """
(text) => {
  let el = document.getElementById('dpdp-caption');
  if (!el) {
    el = document.createElement('div'); el.id = 'dpdp-caption';
    el.style.cssText = 'position:fixed;left:24px;right:24px;bottom:20px;z-index:99999;background:rgba(17,24,39,.92);'
      + 'color:#fff;font:500 21px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;padding:14px 20px;border-radius:10px;'
      + 'box-shadow:0 6px 24px rgba(0,0,0,.25);transition:opacity .3s';
    document.body.appendChild(el);
  }
  el.textContent = text; el.style.opacity = text ? 1 : 0;
}
"""
CARD_HTML = """<!DOCTYPE html><html><body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:#1e2a5a;color:#fff;font-family:system-ui,-apple-system,Segoe UI,sans-serif"><div style="max-width:900px;
padding:40px"><div style="font-size:40px;font-weight:700;margin-bottom:22px">{title}</div><div style="font-size:24px;
line-height:1.5;white-space:pre-line;opacity:.92">{body}</div></div></body></html>"""

SCROLL_JS = """
async ([y, ms]) => {
  const start = window.scrollY, dist = y - start, t0 = performance.now();
  await new Promise(done => { function step(t) { const k = Math.min(1, (t - t0) / ms);
    window.scrollTo(0, start + dist * (k < .5 ? 2*k*k : 1 - Math.pow(-2*k + 2, 2) / 2));
    k < 1 ? requestAnimationFrame(step) : done(); } requestAnimationFrame(step); });
}
"""


def record(report: Path, output: Path, chrome: str | None, width: int, height: int) -> Path:
    from playwright.sync_api import sync_playwright

    access = report.parent / "rights" / "access-report-rahul.html"
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chrome) if chrome else p.chromium.launch()
        ctx = browser.new_context(viewport={"width": width, "height": height},
                                  record_video_dir=tmp, record_video_size={"width": width, "height": height})
        page = ctx.new_page()

        def card(title, body, seconds):
            page.set_content(CARD_HTML.format(title=title, body=body))
            page.wait_for_timeout(int(seconds * 1000))

        card(*INTRO, 6)
        page.goto(report.resolve().as_uri())
        page.wait_for_timeout(800)
        sections = page.locator("section")
        for i, text in enumerate(CAPTIONS):
            if i >= sections.count():
                break
            top = page.evaluate("(i) => document.querySelectorAll('section')[i].getBoundingClientRect().top + window.scrollY - 16", i)
            h = page.evaluate("(i) => document.querySelectorAll('section')[i].getBoundingClientRect().height", i)
            page.evaluate(OVERLAY_JS, "")                      # no stale caption while moving on
            page.evaluate(SCROLL_JS, [top, 1200])
            page.evaluate(OVERLAY_JS, text)
            page.wait_for_timeout(3500)
            extra = max(0, h - (height - 140))                 # long sections: scroll through them slowly
            if extra:
                page.evaluate(SCROLL_JS, [top + extra, int(min(9000, 2500 + extra * 6))])
            page.wait_for_timeout(4500 if not extra else 2500)
        if access.exists():
            page.evaluate(OVERLAY_JS, "")
            page.goto(access.resolve().as_uri())
            page.evaluate(OVERLAY_JS, ACCESS)
            page.wait_for_timeout(3500)
            page.evaluate(SCROLL_JS, [900, 5000])
            page.wait_for_timeout(2000)
        card(*OUTRO, 6)
        video = page.video.path()
        ctx.close()
        browser.close()
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", video, "-c:v", "libx264", "-preset", "veryfast",
                        "-crf", "28", "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(output)], check=True)
    return output


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=".dpdp/report.html")
    ap.add_argument("--output", default=".dpdp/demo-tour.mp4")
    ap.add_argument("--chrome", help="path to an installed Chrome/Chromium")
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=720)
    a = ap.parse_args()
    if not Path(a.report).exists():
        raise SystemExit(f"{a.report} not found: run demo.py --html first")
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg is required on the PATH")
    print(record(Path(a.report), Path(a.output), a.chrome, a.width, a.height))


if __name__ == "__main__":
    main()
