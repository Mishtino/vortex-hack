"""Compare two saved Vortex reports offline, with conservative resolution tracking."""
import argparse
from collections import defaultdict
import datetime
from html import escape
import json
from pathlib import Path

from vortex import VERSION, finding_id, validate_url

MAX_BYTES = 5 * 1024 * 1024
SEVERITIES = {'medium', 'low', 'review', 'info'}
STATES = ('new', 'changed', 'persistent', 'resolved', 'unverified')


def require_text(value, label, limit=5000):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f'{label} must be nonempty text, at most {limit} characters.')
    return value


def validate_report(data):
    if not isinstance(data, dict) or data.get('schema_version') != 2 or data.get('tool') != 'Vortex Hack':
        raise ValueError('Expected a Vortex Hack JSON report with schema_version 2.')
    require_text(data.get('version'), 'version', 100)
    require_text(data.get('time_utc'), 'time_utc', 100)
    if not isinstance(data.get('demo'), bool):
        raise ValueError('Report demo flag must be a boolean.')
    results = data.get('results')
    if not isinstance(results, list) or not results or len(results) > 100:
        raise ValueError('Report must contain 1–100 results.')
    seen = set()
    for result in results:
        if not isinstance(result, dict):
            raise ValueError('Every result must be an object.')
        target = require_text(result.get('target'), 'target', 2048)
        validate_url(target)
        if target in seen:
            raise ValueError('A report contains duplicate target URLs.')
        seen.add(target)
        outcome = result.get('outcome')
        status = result.get('status')
        if outcome not in ('completed', 'error'):
            raise ValueError('Invalid target outcome.')
        if outcome == 'completed' and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError('Completed targets need a valid HTTP status.')
        if outcome == 'error' and status is not None:
            raise ValueError('Connection error status must be null.')
        findings = result.get('findings')
        if not isinstance(findings, list) or len(findings) > 1000 or (outcome == 'error' and findings):
            raise ValueError('Invalid findings list.')
        for item in findings:
            if not isinstance(item, dict) or not isinstance(item.get('severity'), str) or item['severity'] not in SEVERITIES:
                raise ValueError('Invalid finding severity.')
            for field in ('check', 'evidence', 'recommendation'):
                require_text(item.get(field), 'finding.' + field)
        assessment = result.get('assessment')
        if assessment is not None:
            if not isinstance(assessment, dict):
                raise ValueError('assessment must be an object.')
            if assessment.get('method') != 'HEAD' or type(assessment.get('status')) is not int or assessment['status'] != status:
                raise ValueError('Assessment method or status does not match the result.')
            require_text(assessment.get('profile'), 'assessment.profile', 100)
            if not isinstance(assessment.get('media_type'), str) or len(assessment['media_type']) > 200:
                raise ValueError('Invalid assessment media type.')
    return data


def load_report(path):
    # Read at most the cap, even if the file changes during the read.
    with path.open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Report exceeds the 5 MiB comparison limit.')
    try:
        return validate_report(json.loads(raw))
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid report encoding or structure.') from error


def groups(result):
    grouped = defaultdict(list)
    if result:
        for item in result['findings']:
            # IDs are recomputed, never trusted from imported reports.
            grouped[item['check']].append({key: item[key] for key in ('severity', 'evidence', 'recommendation')})
    for values in grouped.values():
        values.sort(key=lambda value: json.dumps(value, sort_keys=True))
    return grouped


def comparable(before, after):
    if not before or not after:
        return False
    if before['outcome'] != 'completed' or after['outcome'] != 'completed':
        return False
    if not 200 <= before['status'] < 300 or not 200 <= after['status'] < 300:
        return False
    old = before.get('assessment')
    new = after.get('assessment')
    # Legacy reports lack coverage evidence; they cannot establish resolution.
    return bool(old and new and old == new)


def compare_reports(baseline, current):
    validate_report(baseline)
    validate_report(current)
    if baseline['demo'] != current['demo']:
        raise ValueError('Demonstration and real scan reports cannot be compared together.')
    old = {item['target']: item for item in baseline['results']}
    new = {item['target']: item for item in current['results']}
    entries = []
    for target in sorted(set(old) | set(new)):
        old_groups, new_groups = groups(old.get(target)), groups(new.get(target))
        for check in sorted(set(old_groups) | set(new_groups)):
            previous, latest = old_groups.get(check, []), new_groups.get(check, [])
            if previous and latest:
                state = 'persistent' if previous == latest else 'changed'
                reason = 'Observation remains present.' if state == 'persistent' else 'Evidence, severity, recommendation or occurrence count changed.'
            elif latest:
                state, reason = 'new', 'Observation appears in the current report.'
            elif comparable(old.get(target), new.get(target)):
                state, reason = 'resolved', 'Not observed in a successful response with matching assessment coverage.'
            else:
                state, reason = 'unverified', 'No matching successful assessment; absence does not establish a fix.'
            entries.append({'id': finding_id(target, check), 'target': target, 'check': check,
                            'state': state, 'reason': reason, 'before': previous, 'after': latest})
    return {'schema_version': 1, 'type': 'vortex-comparison', 'version': VERSION,
            'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'demo': current['demo'],
            'baseline_time': baseline['time_utc'], 'current_time': current['time_utc'],
            'summary': {state: sum(item['state'] == state for item in entries) for state in STATES},
            'target_summary': {'baseline': len(old), 'current': len(new),
                               'added': len(set(new) - set(old)), 'omitted': len(set(old) - set(new))},
            'limitations': 'Counts group observations by exact target URL and check. Resolved means not observed under matching coverage, not proof that a vulnerability is fixed. Report authenticity is not verified. Legacy reports without assessment metadata cannot establish resolution.',
            'entries': entries}


def render_comparison(report):
    def e(value):
        return escape(str(value), quote=True)

    metrics = ''.join(f'<div class="metric"><b>{e(report["summary"][state])}</b><span>{state.title()}</span></div>' for state in STATES)
    entries = []
    for item in report['entries']:
        columns = []
        for label, key in [('Baseline', 'before'), ('Current', 'after')]:
            content = ''.join(f'<div class="observation"><strong>{e(f["severity"].upper())}</strong><p>{e(f["evidence"])}</p><small>Action</small><p>{e(f["recommendation"])}</p></div>' for f in item[key])
            columns.append(f'<div><h4>{label} · {len(item[key])} occurrence(s)</h4>{content or "<p>No observation recorded.</p>"}</div>')
        entries.append(f'<section><div class="heading"><span class="badge">{e(item["state"].upper())}</span><code>{e(item["id"])}</code></div><h2>{e(item["check"].replace("_", " "))}</h2><p class="url">{e(item["target"])}</p><p>{e(item["reason"])}</p><div class="columns">{"".join(columns)}</div></section>')
    demo = '<div class="demo">DEMONSTRATION DATA · No systems were scanned</div>' if report['demo'] else ''
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Vortex Hack · Review changes</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080f1c;color:#edf4ff;font:15px/1.6 system-ui,sans-serif}main{max-width:1120px;margin:auto;padding:40px 24px}nav{letter-spacing:.15em;border-bottom:1px solid #283a53;padding-bottom:20px;font-weight:800}nav span,small{color:#57e1eb}header{padding:40px 0 20px}h1{font-size:clamp(32px,6vw,50px);line-height:1.15;margin:12px 0;letter-spacing:-.035em}h2{font-size:19px;margin:12px 0 4px}h4{font-size:13px;color:#d9e8ff;margin:8px 0 15px}p{color:#acbad0;margin:9px 0}.url{overflow-wrap:anywhere;color:#57e1eb}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0 30px}.metric{background:#111d30;border:1px solid #283a53;border-radius:10px;padding:20px}.metric b{font-size:32px;display:block}.metric span{color:#acbad0;font-size:12px}section{padding:24px;margin:20px 0;border:1px solid #283a53;background:#111d30;border-radius:12px}.heading{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.badge{background:#203e50;color:#99e9f4;padding:5px 10px;border-radius:5px;font-size:10px;font-weight:800;letter-spacing:.08em}code{font-size:11px;color:#acbad0}.columns{display:grid;grid-template-columns:1fr 1fr;gap:24px;border-top:1px solid #283a53;margin-top:22px;padding-top:14px}.observation{border-left:2px solid #405a74;padding-left:13px;margin-bottom:20px}.observation strong{font-size:10px;color:#d9e8ff}.observation p{font-size:13px}aside{border:1px dashed #405a74;border-radius:10px;padding:24px;margin-top:30px}aside p{font-size:13px}.demo{margin-top:20px;background:#473519;color:#ffe3a7;padding:12px;border-radius:7px}footer{font-size:11px;color:#acbad0;margin-top:28px}@media(max-width:700px){.metrics{grid-template-columns:repeat(2,1fr)}.columns{grid-template-columns:1fr}main{padding:25px 16px}}@media print{body{background:white;color:#182238}section,.metric{background:white}p{color:#334155}section{break-inside:avoid}}</style></head><body><main><nav>VORTEX <span>HACK</span> / REVIEW CHANGES</nav>''' + demo + f'''<header><small>CONTINUOUS SECURITY REVIEW</small><h1>See what changed.<br>Verify what improved.</h1><p>Baseline: {e(report['baseline_time'])}<br>Current: {e(report['current_time'])}</p></header><div class="metrics">{metrics}</div>{''.join(entries) or '<section>No observations in either report.</section>'}<aside><strong>Interpretation</strong><p>{e(report['limitations'])}</p><p>Targets: {e(report['target_summary']['baseline'])} baseline / {e(report['target_summary']['current'])} current · {e(report['target_summary']['added'])} added · {e(report['target_summary']['omitted'])} omitted</p></aside><footer>Vortex Technologies · Offline comparison · No external assets or telemetry</footer></main></body></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--current', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=Path('vortex-comparison.json'))
    parser.add_argument('--html', type=Path)
    parser.add_argument('--fail-on-new', action='store_true', help='Return exit 2 if new or changed observations exist')
    args = parser.parse_args(argv)
    try:
        destinations = [path for path in [args.output, args.html] if path is not None]
        if len({path.resolve() for path in destinations}) != len(destinations):
            raise ValueError('JSON and HTML output paths must differ.')
        if any(path.exists() for path in destinations):
            raise ValueError('An output path already exists; choose new filenames.')
        report = compare_reports(load_report(args.baseline), load_report(args.current))
        with args.output.open('x', encoding='utf-8') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        if args.html:
            with args.html.open('x', encoding='utf-8') as output:
                output.write(render_comparison(report))
    except (OSError, ValueError, TypeError, RecursionError) as error:
        parser.exit(1, 'Comparison failed: ' + str(error) + '\n')
    print('Vortex comparison | ' + ' | '.join(f'{count} {state}' for state, count in report['summary'].items()))
    print('JSON: ' + str(args.output))
    if args.html:
        print('HTML: ' + str(args.html))
    return 2 if args.fail_on_new and (report['summary']['new'] or report['summary']['changed']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
