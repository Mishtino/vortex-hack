import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vortex import build_report, finding_id
from vortex_compare import compare_reports, load_report, main, render_comparison, validate_report


def finding(check='missing_content-security-policy', **changes):
    value = {'check': check, 'severity': 'medium', 'evidence': 'Policy was absent.',
             'recommendation': 'Define and test a policy.'}
    value.update(changes)
    return value


def report(findings, target='https://example.com/', **changes):
    result = {'target': target, 'outcome': 'completed', 'status': 200, 'findings': findings,
              'assessment': {'profile': 'head-config-v2', 'method': 'HEAD', 'status': 200, 'media_type': 'text/html'}}
    result.update(changes)
    return build_report([result])


class ComparisonTests(unittest.TestCase):
    def test_ids_ignore_order_and_recommendations(self):
        self.assertEqual(finding_id('https://example.com/', 'a'), finding_id('https://example.com/', 'a'))
        self.assertNotEqual(finding_id('https://example.com/', 'a'), finding_id('https://example.com/', 'b'))
        one = report([finding()])
        two = report([finding(recommendation='Updated guidance.')])
        self.assertEqual(one['results'][0]['findings'][0]['id'], two['results'][0]['findings'][0]['id'])

    def test_new_persistent_changed_and_resolved(self):
        old = report([finding('same'), finding('gone'), finding('modified')])
        new = report([finding('same'), finding('added'), finding('modified', severity='low')])
        comparison = compare_reports(old, new)
        self.assertEqual(comparison['summary'], {'new': 1, 'changed': 1, 'persistent': 1, 'resolved': 1, 'unverified': 0})

    def test_failure_redirect_and_coverage_changes_cannot_resolve(self):
        old = report([finding()])
        changes = [
            {'outcome': 'error', 'status': None, 'assessment': None},
            {'status': 302, 'assessment': {'profile': 'head-config-v2', 'method': 'HEAD', 'status': 302, 'media_type': 'text/html'}},
            {'status': 405, 'assessment': {'profile': 'head-config-v2', 'method': 'HEAD', 'status': 405, 'media_type': 'text/html'}},
            {'assessment': {'profile': 'head-config-v2', 'method': 'HEAD', 'status': 200, 'media_type': 'application/json'}},
            {'assessment': {'profile': 'changed-engine', 'method': 'HEAD', 'status': 200, 'media_type': 'text/html'}},
            {'assessment': None},
        ]
        for change in changes:
            with self.subTest(change=change):
                result = compare_reports(old, report([], **change))
                self.assertEqual(result['summary']['unverified'], 1)
                self.assertEqual(result['summary']['resolved'], 0)

    def test_omitted_target_does_not_resolve(self):
        comparison = compare_reports(report([finding()]), report([], target='https://other.example/'))
        self.assertEqual(comparison['summary']['unverified'], 1)
        self.assertEqual(comparison['target_summary']['omitted'], 1)

    def test_cookie_occurrences_are_counted(self):
        old = report([finding('cookie_attributes'), finding('cookie_attributes')])
        current = report([finding('cookie_attributes')])
        result = compare_reports(old, current)
        self.assertEqual(result['summary']['changed'], 1)
        self.assertEqual(len(result['entries'][0]['before']), 2)
        self.assertEqual(len(result['entries'][0]['after']), 1)

    def test_legacy_report_remains_readable_but_cannot_resolve(self):
        old = report([finding()])
        del old['results'][0]['assessment']
        old['version'] = '0.2.0'
        result = compare_reports(old, report([]))
        self.assertEqual(result['summary']['unverified'], 1)

    def test_demo_and_real_cannot_be_mixed(self):
        current = report([])
        current['demo'] = True
        with self.assertRaises(ValueError):
            compare_reports(report([]), current)

    def test_malformed_and_duplicate_results_rejected(self):
        cases = [{}, {'schema_version': 1}]
        duplicate = report([])
        duplicate['results'].append(copy.deepcopy(duplicate['results'][0]))
        cases.append(duplicate)
        bad_status = report([])
        bad_status['results'][0]['status'] = True
        cases.append(bad_status)
        bad_assessment = report([])
        bad_assessment['results'][0]['assessment']['status'] = 302
        cases.append(bad_assessment)
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_report(data)

    def test_imported_ids_are_not_trusted_and_html_is_escaped(self):
        current = report([finding(evidence='<script>bad()</script>', recommendation='<img>')])
        current['results'][0]['findings'][0]['id'] = '<script>FAKE</script>'
        comparison = compare_reports(report([]), current)
        html = render_comparison(comparison)
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img>', html)
        self.assertNotIn('FAKE', html)
        self.assertIn('&lt;script&gt;', html)

    def test_report_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'large.json'
            path.write_bytes(b' ' * 200)
            with patch('vortex_compare.MAX_BYTES', 100), self.assertRaises(ValueError):
                load_report(path)

    def test_cli_is_offline_and_protects_inputs(self):
        with tempfile.TemporaryDirectory() as folder, patch('vortex.scan') as scan:
            root = Path(folder)
            baseline, current = root / 'before.json', root / 'after.json'
            baseline.write_text(json.dumps(report([])))
            current.write_text(json.dumps(report([finding()])))
            args = ['--baseline', str(baseline), '--current', str(current), '--output', str(root / 'diff.json'),
                    '--html', str(root / 'diff.html'), '--fail-on-new']
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(json.loads((root / 'diff.json').read_text())['summary']['new'], 1)
            self.assertTrue((root / 'diff.html').is_file())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['--baseline', str(baseline), '--current', str(current), '--output', str(baseline)])
            scan.assert_not_called()


if __name__ == '__main__':
    unittest.main()
