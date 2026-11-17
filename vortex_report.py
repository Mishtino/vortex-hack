"""Self-contained, escaped HTML reports. No scripts, remote assets or telemetry."""
from html import escape


def render_html(report):
    def e(value):
        return escape(str(value), quote=True)

    summary = report['summary']
    demo = '<div class="demo">DEMONSTRATION DATA · No systems were scanned</div>' if report.get('demo') else ''
    cards = ''.join(f'<div class="metric"><strong>{e(value)}</strong><span>{e(label)}</span></div>'
                    for label, value in [('Targets', summary['targets']), ('Completed', summary['completed']),
                                         ('Findings', summary['findings']), ('Connection errors', summary['errors'])])
    targets = []
    for index, result in enumerate(report['results'], 1):
        findings = []
        for finding in result['findings']:
            severity = finding['severity']
            style = severity if severity in ('medium', 'low', 'review', 'info') else 'info'
            findings.append(f'''<article class="finding"><div class="finding-head"><span class="badge {style}">{e(severity)}</span>
<h3>{e(finding['check'].replace('_', ' '))}</h3></div>
<p>{e(finding['evidence'])}</p><div class="fix"><strong>Recommended action</strong><p>{e(finding['recommendation'])}</p></div></article>''')
        if result['outcome'] == 'error':
            content = '<p class="error">' + e(result['error']) + '</p>'
        else:
            content = ''.join(findings) or '<p class="clear">No issues observed by the checks performed. Coverage is limited.</p>'
        status = 'HTTP ' + str(result['status']) if result['status'] is not None else 'UNAVAILABLE'
        targets.append(f'''<section class="target"><div class="target-head"><div><small>APPROVED TARGET {index:02d}</small>
<h2>{e(result['target'])}</h2></div><span class="status">{e(status)}</span></div>{content}</section>''')
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Vortex Hack · Security review</title><style>
:root{color-scheme:dark;--bg:#080f1c;--panel:#111d30;--line:#283a53;--text:#edf4ff;--muted:#acbad0;--cyan:#57e1eb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:44px 26px}
nav{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:20px}.brand{letter-spacing:.16em;font-weight:800}.brand b{color:var(--cyan)}nav span{font-size:12px;color:var(--muted)}
.hero{padding:50px 0 30px}.eyebrow,small{color:var(--cyan);letter-spacing:.12em;font-size:11px;font-weight:700}h1{font-size:clamp(32px,6vw,52px);line-height:1.12;letter-spacing:-.04em;margin:14px 0}h2{font-size:18px;margin:7px 0;overflow-wrap:anywhere}h3{font-size:16px;margin:0}p{color:var(--muted);margin:9px 0}.subtitle{max-width:680px}.demo{background:#473519;color:#ffe3a7;border:1px solid #836632;padding:12px 18px;border-radius:8px;margin-top:20px;font-size:13px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:16px 0 36px}.metric{padding:24px;border:1px solid var(--line);background:var(--panel);border-radius:12px}.metric strong{display:block;font-size:36px;line-height:1.3}.metric span{color:var(--muted);font-size:13px}
.target{border:1px solid var(--line);border-radius:12px;margin:20px 0;overflow:hidden;background:var(--panel)}.target-head{padding:22px 24px;display:flex;justify-content:space-between;gap:14px;border-bottom:1px solid var(--line)}.status{white-space:nowrap;font-size:11px;color:var(--muted);align-self:center}.finding{padding:23px 24px;border-bottom:1px solid var(--line)}.finding:last-child{border:0}.finding-head{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.badge{font-size:10px;font-weight:800;padding:4px 9px;border-radius:5px;text-transform:uppercase;letter-spacing:.06em}.medium{background:#503c21;color:#ffda95}.low{background:#173e50;color:#99dfff}.review{background:#342955;color:#ddc5ff}.info{background:#29394a;color:#c9d9eb}.fix{border-left:2px solid var(--cyan);padding-left:14px;margin-top:18px}.fix strong{font-size:12px;color:var(--text)}.fix p{font-size:14px}.error,.clear{padding:8px 24px 22px}.error{color:#ffb7b7}.limitations{padding:24px;border:1px dashed var(--line);border-radius:12px;margin-top:32px}.limitations p{font-size:13px}footer{display:flex;justify-content:space-between;gap:15px;color:var(--muted);font-size:11px;margin-top:30px}
@media(max-width:650px){main{padding:25px 16px}.metrics{grid-template-columns:repeat(2,1fr)}.metric{padding:18px}.target-head{flex-direction:column}.status{align-self:flex-start}.finding,.target-head{padding:20px}footer{flex-direction:column}}@media print{body{background:white;color:#182238}p,footer{color:#334155}.target,.metric{background:white;break-inside:avoid}.hero{padding:25px 0}nav span{color:#334155}}
</style></head><body><main><nav><div class="brand">VORTEX <b>HACK</b></div><span>VORTEX TECHNOLOGIES / SECURITY TOOLKIT</span></nav>''' + demo + f'''
<header class="hero"><div class="eyebrow">WEBSITE CONFIGURATION REVIEW</div><h1>Understand your exposure.<br>Prioritize your next fix.</h1><p class="subtitle">Evidence from bounded checks on approved URLs. Each observation includes a practical action for review.</p><p><small>VERSION {e(report['version'])} · {e(report['time_utc'])}</small></p></header>
<div class="metrics">{cards}</div>{''.join(targets)}<aside class="limitations"><strong>Coverage & interpretation</strong><p>{e(report['limitations'])}</p></aside>
<footer><span>Vortex Technologies · Vortex Hack</span><span>Private report · No external assets or telemetry</span></footer></main></body></html>'''
