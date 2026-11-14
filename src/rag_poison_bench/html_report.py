from __future__ import annotations

import html
from typing import List, Tuple
from .benchmark import MetricSummary
from .data.benchmark_dataset import BenchmarkSample
from .engine import ScanResult


def generate_html_report(
    summary: MetricSummary,
    detailed_results: List[Tuple[BenchmarkSample, ScanResult]] | None = None,
) -> str:
    """Generates a standalone, interactive HTML security scorecard and visual chunk inspector."""
    rec_pct = f"{summary.recall * 100:.1f}%"
    fpr_pct = f"{summary.fpr * 100:.1f}%"
    prec_pct = f"{summary.precision * 100:.1f}%"
    f1_val = f"{summary.f1:.4f}"
    speed_cps = f"{summary.scan_throughput_cps:,.1f}"

    category_rows = []
    for cat, score in sorted(summary.category_recall.items()):
        pct = score * 100.0
        bar_color = "#10b981" if pct >= 90 else "#f59e0b" if pct >= 70 else "#ef4444"
        category_rows.append(f"""
        <div class="cat-row">
            <div class="cat-label"><code>{html.escape(cat)}</code> <span>{pct:.1f}%</span></div>
            <div class="cat-bar-bg">
                <div class="cat-bar-fill" style="width: {pct:.1f}%; background: {bar_color};"></div>
            </div>
        </div>
        """)

    # Build chunk cards
    chunk_cards = []
    if detailed_results:
        for idx, (sample, res) in enumerate(detailed_results, 1):
            is_match = (sample.is_poisoned == res.is_poisoned)
            status_tag = "CLEAN"
            tag_color = "#10b981"
            if sample.is_poisoned and res.is_poisoned:
                status_tag = "POISONED (DETECTED)"
                tag_color = "#ef4444"
            elif sample.is_poisoned and not res.is_poisoned:
                status_tag = "MISSED DETECTION (FN)"
                tag_color = "#f97316"
            elif not sample.is_poisoned and res.is_poisoned:
                status_tag = "FALSE POSITIVE (FP)"
                tag_color = "#eab308"

            # Render text with highlighted spans
            text_escaped = html.escape(sample.text)
            if res.findings:
                # Highlight findings from end to start to preserve indices
                sorted_findings = sorted(res.findings, key=lambda f: f.char_span[0], reverse=True)
                for f in sorted_findings:
                    s_idx, e_idx = f.char_span
                    if 0 <= s_idx < e_idx <= len(sample.text):
                        target_sub = html.escape(sample.text[s_idx:e_idx])
                        desc_tip = html.escape(f"[{f.severity.value.upper()}] {f.detector}: {f.description}")
                        highlighted = f'<mark class="threat-span threat-{f.severity.value}" title="{desc_tip}">{target_sub}</mark>'
                        # Replace occurrence
                        text_escaped = text_escaped[:s_idx] + highlighted + text_escaped[e_idx:]

            chunk_cards.append(f"""
            <div class="chunk-card" data-poisoned="{str(sample.is_poisoned).lower()}">
                <div class="chunk-header">
                    <span class="chunk-id">#{idx} {html.escape(sample.id)}</span>
                    <span class="badge" style="background: {tag_color}22; color: {tag_color}; border: 1px solid {tag_color}55;">{status_tag}</span>
                </div>
                <div class="chunk-body">{text_escaped}</div>
                {f'<div class="chunk-meta">Findings: {len(res.findings)} | Threat Score: {res.score:.2f}</div>' if res.findings else ''}
            </div>
            """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RAG Poison Bench - Visual Evaluation Report</title>
<style>
  :root {{
    --bg: #090d16;
    --card-bg: #111827;
    --border: #1f2937;
    --text-main: #f3f4f6;
    --text-muted: #9ca3af;
    --accent: #3b82f6;
    --danger: #ef4444;
    --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text-main);
    padding: 32px 16px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1040px; margin: 0 auto; }}
  .header {{ margin-bottom: 28px; text-align: center; }}
  .title {{ font-size: 26px; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  .subtitle {{ color: var(--text-muted); font-size: 14px; }}
  
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .kpi-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    text-align: center;
  }}
  .kpi-val {{ font-size: 28px; font-weight: 800; color: #fff; }}
  .kpi-val.green {{ color: #10b981; }}
  .kpi-lbl {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-top: 4px; letter-spacing: 0.5px; }}
  
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  .card-title {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
  
  .cat-row {{ margin-bottom: 14px; }}
  .cat-label {{ display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 6px; }}
  .cat-bar-bg {{ background: #1f2937; height: 8px; border-radius: 4px; overflow: hidden; }}
  .cat-bar-fill {{ height: 100%; border-radius: 4px; }}

  .chunk-card {{
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 12px;
    font-size: 13px;
  }}
  .chunk-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .chunk-id {{ font-family: monospace; color: var(--text-muted); }}
  .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
  .chunk-body {{ font-family: ui-monospace, SFMono-Regular, monospace; color: #e2e8f0; line-height: 1.6; white-space: pre-wrap; }}
  .chunk-meta {{ font-size: 11px; color: var(--text-muted); margin-top: 8px; }}
  
  mark.threat-span {{
    background: #ef444433;
    color: #fca5a5;
    border-bottom: 2px solid #ef4444;
    padding: 1px 3px;
    border-radius: 2px;
    cursor: help;
  }}
  mark.threat-critical {{ background: #dc262644; border-bottom: 2px solid #dc2626; color: #fecaca; }}
  mark.threat-high {{ background: #ea580c44; border-bottom: 2px solid #ea580c; color: #fed7aa; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1 class="title">🛡️ RAG Poison Bench Evaluation</h1>
    <p class="subtitle">Indirect Prompt Injection & Retrieval Security Benchmark Report</p>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-val green">{rec_pct}</div>
      <div class="kpi-lbl">Recall (TPR)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val green">{fpr_pct}</div>
      <div class="kpi-lbl">False Positive (FPR)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">{prec_pct}</div>
      <div class="kpi-lbl">Precision</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">{f1_val}</div>
      <div class="kpi-lbl">F1 Score</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-val">{speed_cps}</div>
      <div class="kpi-lbl">Chunks / Sec</div>
    </div>
  </div>

  <div class="card">
    <h2 class="card-title">Attack Vector Coverage</h2>
    {"".join(category_rows)}
  </div>

  <div class="card">
    <h2 class="card-title">Curated Document Chunks & Detected Payloads ({summary.total} Total)</h2>
    {"".join(chunk_cards)}
  </div>
</div>
</body>
</html>
"""
    return html_content
