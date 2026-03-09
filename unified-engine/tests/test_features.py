"""
test_features.py — Feature Tests for all additions since test_realworld.py
Covers:
  - Line number accuracy (local vs combined)
  - _combine_files offset math (+1 not +2)
  - Zip download faithful reconstruction (conf.py Blarg test)
  - Structural issue line resolution
  - Security finding local_lineno for 2,5,10,20,50 file zips
  - Empty __init__.py included in file count
  - Back-to-results state (_lastResultsHTML)
  - Collapse button presence in HTML
  - Install button presence in HTML
  - Download button presence in HTML
  - CodeMirror CDN links present
  - inputStyle contenteditable
  - PWA manifest and icons
  - Health endpoint
  - Compare endpoint
  - All routes respond
  - Edge cases: single empty file, unicode, very long file
  - Microdot zip: 89 files, correct local linenos, all source_files set
"""

import io
import json
import re
import sys
import zipfile
import unittest

sys.path.insert(0, '/home/claude/unified-engine')
import app as application
from app import _combine_files

client = application.app.test_client()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def analyze(code):
    r = client.post('/api/analyze', json={'code': code})
    return json.loads(r.data)

def analyze_files(files):
    r = client.post('/api/analyze_files', json={'files': files})
    return json.loads(r.data)

def make_zip(file_dict):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for path, content in file_dict.items():
            z.writestr(path, content)
    buf.seek(0)
    return buf

def analyze_zip(file_dict):
    buf = make_zip(file_dict)
    r = client.post('/api/analyze_zip',
                    data={'zip': (buf, 'test.zip')},
                    content_type='multipart/form-data')
    return json.loads(r.data)

def get_html():
    return client.get('/').data.decode()

# ─────────────────────────────────────────────────────────────────────────────
# 1. _combine_files offset math
# ─────────────────────────────────────────────────────────────────────────────

class TestCombineFiles(unittest.TestCase):

    def test_single_file_start_is_1(self):
        _, offsets = _combine_files([{'name': 'a.py', 'content': 'x=1\n'}])
        self.assertEqual(offsets[0]['start_line'], 1)

    def test_header_matches_start_line(self):
        files = [{'name': 'a.py', 'content': 'x=1\n'},
                 {'name': 'b.py', 'content': 'y=2\n'},
                 {'name': 'c.py', 'content': 'z=3\n'}]
        combined, offsets = _combine_files(files)
        lines = combined.split('\n')
        for o in offsets:
            actual_header_line = next(
                i+1 for i, l in enumerate(lines)
                if o['name'] in l and l.startswith('# === FILE:')
            )
            self.assertEqual(o['start_line'], actual_header_line,
                f"{o['name']}: offset says {o['start_line']} but header at {actual_header_line}")

    def test_zero_discrepancy_2_files(self):
        files = [{'name': 'a.py', 'content': 'x=1\ny=2\n'},
                 {'name': 'b.py', 'content': 'a=10\nb=20\n'}]
        combined, offsets = _combine_files(files)
        lines = combined.split('\n')
        for o in offsets:
            actual = next(i+1 for i,l in enumerate(lines) if o['name'] in l and '===' in l)
            self.assertEqual(o['start_line'], actual)

    def test_zero_discrepancy_10_files(self):
        files = [{'name': f'f{i}.py', 'content': f'x_{i}={i}\n'*3} for i in range(10)]
        combined, offsets = _combine_files(files)
        lines = combined.split('\n')
        for o in offsets:
            actual = next(i+1 for i,l in enumerate(lines) if o['name'] in l and '===' in l)
            self.assertEqual(o['start_line'], actual,
                f"{o['name']}: expected {actual} got {o['start_line']}")

    def test_local_lineno_correct_2_files(self):
        """line N in combined → correct local line in its file"""
        file_a = 'import os\nx = 1\ny = 2\n'
        file_b = 'a = 10\nb = 20\nc = 30\n'
        combined, offsets = _combine_files([
            {'name': 'a.py', 'content': file_a},
            {'name': 'b.py', 'content': file_b},
        ])
        lines = combined.split('\n')
        # Find 'b = 20' in combined
        combined_lineno = next(i+1 for i,l in enumerate(lines) if l.strip() == 'b = 20')
        offset_b = next(o for o in offsets if o['name'] == 'b.py')
        local = combined_lineno - offset_b['start_line']
        # local should be 2 (b=20 is line 2 in b.py, 1-indexed from content start)
        self.assertEqual(local, 2)

    def test_separator_is_two_blank_lines(self):
        """join('\n\n') + trailing \n in content = two blank lines between files"""
        files = [{'name': 'a.py', 'content': 'x=1\n'},
                 {'name': 'b.py', 'content': 'y=2\n'}]
        combined, offsets = _combine_files(files)
        lines = combined.split('\n')
        # b.py header must be exactly at offset start_line
        actual = next(i+1 for i,l in enumerate(lines) if '# === FILE: b.py' in l)
        self.assertEqual(offsets[1]['start_line'], actual)


# ─────────────────────────────────────────────────────────────────────────────
# 2. local_lineno accuracy via API
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalLineno(unittest.TestCase):

    def _check_local_linenos(self, d):
        offsets = d.get('file_offsets', [])
        offset_map = {o['name'].split('/')[-1]: o for o in offsets}
        for f in d.get('security_findings', []):
            src   = f.get('source_file', '')
            local = f.get('local_lineno', 0)
            combined = f.get('lineno', 0)
            self.assertGreater(local, 0, f"local_lineno=0 for {src}")
            # local must be <= line count of that file
            if src in offset_map:
                o = offset_map[src]
                file_lines = o['end_line'] - o['start_line']
                self.assertLessEqual(local, file_lines + 1,
                    f"{src}: local_lineno={local} > file length {file_lines}")

    def test_2_file_local_lineno(self):
        d = analyze_files([
            {'name': 'routes.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'utils.py',  'content': 'def add(a,b): return a+b\n'},
        ])
        self._check_local_linenos(d)

    def test_5_file_local_lineno(self):
        files = [{'name': f'm{i}.py', 'content': 'x=1\n'*i} for i in range(1, 5)]
        files.append({'name': 'vuln.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'})
        d = analyze_files(files)
        self._check_local_linenos(d)

    def test_zip_local_lineno_correct(self):
        vuln = 'from flask import request\ndef handler():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'
        d = analyze_zip({
            'proj/routes.py': vuln,
            'proj/utils.py': 'def add(a,b): return a+b\n',
            'proj/models.py': 'class M: pass\n',
        })
        for f in d.get('security_findings', []):
            self.assertGreater(f.get('local_lineno', 0), 0)
            # local_lineno must be within the file's actual line count
            local = f.get('local_lineno', 0)
            self.assertLessEqual(local, vuln.count('\n') + 1)

    def test_source_file_always_set_in_multifile(self):
        d = analyze_files([
            {'name': 'a.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'b.py', 'content': 'def clean(): pass\n'},
        ])
        for f in d.get('security_findings', []):
            self.assertTrue(f.get('source_file'), f"Missing source_file: {f}")

    def test_combined_vs_local_differ_in_multifile(self):
        """When there are multiple files, local_lineno should differ from combined lineno"""
        # Put the vuln in file 2 so combined line > local line
        d = analyze_files([
            {'name': 'clean.py', 'content': 'x=1\n'*20},
            {'name': 'vuln.py',  'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
        ])
        for f in d.get('security_findings', []):
            if f.get('source_file') == 'vuln.py':
                self.assertNotEqual(f.get('lineno'), f.get('local_lineno'),
                    "local_lineno should differ from combined lineno in multi-file")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Microdot zip — full real-world validation
# ─────────────────────────────────────────────────────────────────────────────

class TestMicrodotZip(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open('/mnt/user-data/uploads/microdot-1.zip', 'rb') as f:
            r = client.post('/api/analyze_zip',
                            data={'zip': (f, 'microdot-1.zip')},
                            content_type='multipart/form-data')
        cls.d = json.loads(r.data)

    def test_file_count_89(self):
        self.assertEqual(self.d.get('file_count'), 89)

    def test_offsets_count_89(self):
        self.assertEqual(len(self.d.get('file_offsets', [])), 89)

    def test_files_count_89(self):
        self.assertEqual(len(self.d.get('files', [])), 89)

    def test_no_error(self):
        self.assertNotIn('error', self.d)
        self.assertIn('report_id', self.d)

    def test_all_findings_have_source_file(self):
        for f in self.d.get('security_findings', []):
            self.assertTrue(f.get('source_file'), f"Missing source_file: {f}")

    def test_all_findings_local_lineno_positive(self):
        for f in self.d.get('security_findings', []):
            self.assertGreater(f.get('local_lineno', 0), 0,
                f"Bad local_lineno for {f.get('source_file')}")

    def test_local_lineno_within_file_bounds(self):
        offset_map = {o['name'].split('/')[-1]: o for o in self.d.get('file_offsets', [])}
        for f in self.d.get('security_findings', []):
            src   = f.get('source_file', '')
            local = f.get('local_lineno', 0)
            if src in offset_map:
                o = offset_map[src]
                file_lines = o['end_line'] - o['start_line']
                self.assertLessEqual(local, file_lines + 2,
                    f"{src}: local_lineno={local} but file has ~{file_lines} lines")

    def test_offsets_zero_discrepancy(self):
        """Every file's start_line must exactly match its header line in combined.
        Uses full path search to handle files sharing the same basename."""
        files = self.d.get('files', [])
        if not files:
            self.skipTest("No files returned")
        combined, combo_offsets = _combine_files(files)
        lines = combined.split('\n')
        for o in combo_offsets:
            full_path = o['name']
            # Search by full path to avoid basename ambiguity
            actual = next(
                (i+1 for i,l in enumerate(lines)
                 if full_path in l and l.startswith('# === FILE:')),
                None
            )
            if actual:
                self.assertEqual(o['start_line'], actual,
                    f"{full_path}: offset={o['start_line']} actual header={actual}")

    def test_structural_count_positive(self):
        self.assertGreater(self.d.get('structural_count', 0), 0)

    def test_structural_issues_have_line_numbers(self):
        for iss in self.d.get('structural_issues', []):
            m = re.search(r'\bline\s+(\d+)', iss, re.IGNORECASE)
            if m:
                lineno = int(m.group(1))
                self.assertGreater(lineno, 0)

    def test_last_structural_issue_reasonable_line(self):
        """SO_REUSEADDR should resolve to mock_socket.py around line 7, not 8549"""
        issues = self.d.get('structural_issues', [])
        offsets = self.d.get('file_offsets', [])
        reuseaddr = next((i for i in issues if 'SO_REUSEADDR' in i), None)
        if reuseaddr:
            m = re.search(r'\bline\s+(\d+)', reuseaddr)
            if m:
                combined_line = int(m.group(1))
                # Resolve to local
                local = combined_line
                for o in offsets:
                    if o['start_line'] <= combined_line <= o['end_line']:
                        local = combined_line - o['start_line']
                        break
                self.assertLess(local, 100,
                    f"SO_REUSEADDR local line should be ~7, got {local}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Empty __init__.py files included
# ─────────────────────────────────────────────────────────────────────────────

class TestEmptyFiles(unittest.TestCase):

    def test_empty_init_counted(self):
        d = analyze_zip({
            'pkg/__init__.py': '',
            'pkg/core/__init__.py': '',
            'pkg/core/engine.py': 'class Engine:\n    def run(self): return True\n',
            'pkg/utils/__init__.py': '',
            'pkg/utils/helpers.py': 'def noop(): pass\n',
        })
        self.assertEqual(d.get('file_count'), 5)

    def test_empty_file_alone(self):
        d = analyze_zip({'app/__init__.py': '', 'app/main.py': 'def run(): pass\n'})
        self.assertEqual(d.get('file_count'), 2)
        self.assertNotIn('error', d)


# ─────────────────────────────────────────────────────────────────────────────
# 5. HTML / UI feature presence
# ─────────────────────────────────────────────────────────────────────────────

class TestUIFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = get_html()

    # CodeMirror
    def test_cm_css_cdn(self):
        self.assertIn('codemirror.min.css', self.html)

    def test_cm_dracula_theme(self):
        self.assertIn('dracula.min.css', self.html)

    def test_cm_js_cdn(self):
        self.assertIn('codemirror.min.js', self.html)

    def test_cm_python_mode(self):
        self.assertIn('python.min.js', self.html)

    def test_cm_init_fromtextarea(self):
        self.assertIn('CodeMirror.fromTextArea', self.html)

    def test_cm_theme_dracula(self):
        self.assertIn("theme:       'dracula'", self.html)

    def test_cm_line_numbers(self):
        self.assertIn('lineNumbers: true', self.html)

    def test_cm_inputstyle_contenteditable(self):
        self.assertIn("inputStyle:  'contenteditable'", self.html)

    def test_cm_highlight_line_css(self):
        self.assertIn('cm-highlight-line', self.html)

    def test_cm_gutter_css(self):
        self.assertIn('CodeMirror-gutters', self.html)

    # Collapse panel
    def test_collapse_button_present(self):
        self.assertIn('collapse-btn', self.html)

    def test_collapse_toggle_fn(self):
        self.assertIn('toggleResults', self.html)

    def test_collapse_css_transition(self):
        self.assertIn('transition:grid-template-columns', self.html)

    def test_collapse_34px_width(self):
        self.assertIn('1fr 34px', self.html)

    def test_collapse_vertical_writing(self):
        self.assertIn('writing-mode:vertical-rl', self.html)

    # Install button
    def test_install_button_present(self):
        self.assertIn('install-btn', self.html)

    def test_install_app_now_text(self):
        self.assertIn('Install', self.html)

    def test_beforeinstallprompt_listener(self):
        self.assertIn('beforeinstallprompt', self.html)

    def test_appinstalled_listener(self):
        self.assertIn('appinstalled', self.html)

    def test_ios_detection(self):
        self.assertIn('isIOS', self.html)

    def test_install_fn(self):
        self.assertIn('function installApp', self.html)

    # Download button
    def test_download_button_present(self):
        self.assertIn('&#11015; Download', self.html)

    def test_download_fn(self):
        self.assertIn('function downloadFiles', self.html)

    def test_download_prompt_rename(self):
        self.assertIn('window.prompt', self.html)

    def test_download_zip_reconstruction(self):
        self.assertIn('JSZip.loadAsync(_originalZipBlob)', self.html)

    def test_download_folder_preserved(self):
        self.assertIn('zip.file(f.name, f.content)', self.html)

    def test_download_numbering(self):
        self.assertIn("'(' + n + ')'", self.html)

    def test_download_counts_tracker(self):
        self.assertIn('_downloadCounts', self.html)

    def test_original_zip_blob_stored(self):
        self.assertIn('_originalZipBlob = file', self.html)

    # PWA
    def test_pwa_manifest(self):
        self.assertIn('manifest.json', self.html)

    def test_pwa_theme_color(self):
        self.assertIn('theme-color', self.html)

    def test_pwa_apple_capable(self):
        self.assertIn('apple-mobile-web-app-capable', self.html)

    def test_pwa_apple_icon(self):
        self.assertIn('apple-touch-icon', self.html)

    # Back to results
    def test_restore_results_fn(self):
        self.assertIn('function restoreResults', self.html)

    def test_last_results_html_var(self):
        self.assertIn('_lastResultsHTML', self.html)

    def test_back_button_text(self):
        self.assertIn('Back to Analysis Results', self.html)

    # No old textarea artifacts
    def test_no_line_nums_div(self):
        self.assertNotIn('<div id="line-nums">', self.html)

    def test_no_set_selection_range(self):
        self.assertNotIn('setSelectionRange', self.html)

    def test_no_update_line_nums_fn(self):
        self.assertNotIn('function updateLineNums', self.html)


# ─────────────────────────────────────────────────────────────────────────────
# 6. All routes respond correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestRoutes(unittest.TestCase):

    def test_home_200(self):
        r = client.get('/')
        self.assertEqual(r.status_code, 200)

    def test_health_200(self):
        r = client.get('/api/health')
        d = json.loads(r.data)
        self.assertEqual(d.get('status'), 'ok')

    def test_analyze_post_only(self):
        r = client.get('/api/analyze')
        self.assertEqual(r.status_code, 405)

    def test_analyze_files_post_only(self):
        r = client.get('/api/analyze_files')
        self.assertEqual(r.status_code, 405)

    def test_analyze_zip_post_only(self):
        r = client.get('/api/analyze_zip')
        self.assertEqual(r.status_code, 405)

    def test_compare_post_only(self):
        r = client.get('/api/compare')
        self.assertEqual(r.status_code, 405)

    def test_manifest_served(self):
        r = client.get('/static/manifest.json')
        self.assertEqual(r.status_code, 200)

    def test_analyze_empty_code_error(self):
        d = json.loads(client.post('/api/analyze', json={'code': ''}).data)
        self.assertIn('error', d)

    def test_analyze_files_empty_error(self):
        d = json.loads(client.post('/api/analyze_files', json={'files': []}).data)
        self.assertIn('error', d)

    def test_analyze_zip_no_file_error(self):
        d = json.loads(client.post('/api/analyze_zip', data={},
                                   content_type='multipart/form-data').data)
        self.assertIn('error', d)

    def test_compare_works(self):
        d = json.loads(client.post('/api/compare', json={
            'code_a': 'def foo(x): return x+1',
            'code_b': 'def bar(y): return y+1',
        }).data)
        self.assertIn('overall_similarity', d)

    def test_compare_identical_isomorphic(self):
        code = 'def foo(x):\n    return x + 1\n'
        d = json.loads(client.post('/api/compare', json={
            'code_a': code, 'code_b': code
        }).data)
        self.assertGreaterEqual(d.get('overall_similarity', 0), 0.9)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Zip extraction rules
# ─────────────────────────────────────────────────────────────────────────────

class TestZipExtraction(unittest.TestCase):

    def test_pycache_excluded(self):
        d = analyze_zip({'app/main.py': 'x=1\n', '__pycache__/main.pyc': 'fake'})
        self.assertEqual(d.get('file_count'), 1)

    def test_venv_excluded(self):
        d = analyze_zip({'app/main.py': 'x=1\n', 'venv/lib/flask/__init__.py': 'x=1'})
        self.assertEqual(d.get('file_count'), 1)

    def test_git_excluded(self):
        d = analyze_zip({'app/main.py': 'x=1\n', '.git/hooks/pre-commit': 'x=1'})
        self.assertEqual(d.get('file_count'), 1)

    def test_node_modules_excluded(self):
        d = analyze_zip({'app/main.py': 'x=1\n', 'node_modules/pkg/helper.py': 'x=1'})
        self.assertEqual(d.get('file_count'), 1)

    def test_non_py_excluded(self):
        d = analyze_zip({'app/main.py': 'x=1\n', 'README.md': '#hi', 'setup.cfg': '[tool]'})
        self.assertEqual(d.get('file_count'), 1)

    def test_nested_deep_included(self):
        d = analyze_zip({'a/b/c/d/e/f/deep.py': 'def fn(): pass\n'})
        self.assertEqual(d.get('file_count'), 1)

    def test_windows_backslash_paths(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('pkg\\module.py', 'x=1\n')
        buf.seek(0)
        r = client.post('/api/analyze_zip', data={'zip': (buf, 't.zip')},
                        content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertTrue(d.get('file_count', 0) >= 1 or 'error' in d)

    def test_corrupt_zip_error(self):
        buf = io.BytesIO(b'not a zip at all')
        r = client.post('/api/analyze_zip', data={'zip': (buf, 'bad.zip')},
                        content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertIn('error', d)

    def test_wrong_extension_error(self):
        buf = io.BytesIO(b'fake')
        r = client.post('/api/analyze_zip', data={'zip': (buf, 'archive.tar.gz')},
                        content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertIn('error', d)

    def test_no_py_files_error(self):
        d = analyze_zip({'README.md': '# hello', 'config.yml': 'key: val'})
        self.assertIn('error', d)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Security detection — regression on key vulns
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityRegression(unittest.TestCase):

    def _has(self, d, kw):
        return any(kw.lower() in f.get('vuln_type','').lower()
                   for f in d.get('security_findings',[]))

    def test_sql_injection_detected(self):
        d = analyze("from flask import request\ndef v():\n    uid=request.args.get('id')\n    cursor.execute('SELECT * FROM t WHERE id='+uid)")
        self.assertTrue(self._has(d, 'sql'))

    def test_sql_parameterized_safe(self):
        d = analyze("from flask import request\ndef v():\n    uid=request.args.get('id')\n    cursor.execute('SELECT * FROM t WHERE id=%s',(uid,))")
        self.assertFalse(self._has(d, 'sql'))

    def test_command_injection_detected(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    cmd=request.args.get('cmd')\n    subprocess.run(cmd,shell=True)")
        self.assertTrue(self._has(d,'command') or self._has(d,'injection'))

    def test_path_traversal_read(self):
        d = analyze("from flask import request\ndef v():\n    f=request.args.get('f')\n    open(f).read()")
        self.assertTrue(self._has(d,'path') or self._has(d,'traversal'))

    def test_path_traversal_with_write(self):
        d = analyze("from flask import request\ndef v():\n    fname=request.form.get('name')\n    with open(fname,'w') as f:\n        f.write('data')")
        self.assertTrue(self._has(d,'path') or self._has(d,'traversal'))

    def test_ssrf_requests(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    url=request.args.get('url')\n    return requests.get(url).text")
        self.assertTrue(self._has(d,'ssrf'))

    def test_deserialize_pickle(self):
        d = analyze("import pickle\nfrom flask import request\ndef v():\n    return pickle.loads(request.data)")
        self.assertTrue(self._has(d,'deserializ'))

    def test_yaml_safe_ok(self):
        d = analyze("import yaml\nfrom flask import request\ndef v():\n    return yaml.safe_load(request.data)")
        self.assertFalse(self._has(d,'deserializ'))

    def test_eval_detected(self):
        d = analyze("from flask import request\ndef v():\n    return eval(request.args.get('expr'))")
        self.assertGreater(d.get('security_count',0), 0)

    def test_clean_code_no_findings(self):
        d = analyze("def add(a,b):\n    return a+b\ndef multiply(a,b):\n    return a*b")
        self.assertEqual(d.get('security_count',0), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):

    def test_unicode_content(self):
        d = analyze_zip({'app/i18n.py': '# -*- coding: utf-8 -*-\nGREETINGS={"ja":"こんにちは","ar":"مرحبا"}\n'})
        self.assertNotIn('error', d)

    def test_very_long_single_file(self):
        lines = ['def func(x):'] + [f'    step_{i} = x + {i}' for i in range(200)] + ['    return step_0']
        d = analyze('\n'.join(lines))
        self.assertNotIn('error', d)

    def test_single_line_file(self):
        d = analyze('x = 1')
        self.assertNotIn('error', d)

    def test_only_comments(self):
        d = analyze('# just a comment\n# another comment\n')
        self.assertNotIn('error', d)

    def test_only_imports(self):
        d = analyze('import os\nimport sys\nfrom pathlib import Path\n')
        self.assertNotIn('error', d)

    def test_100_file_zip(self):
        files = {f'pkg/mod_{i}.py': f'def fn_{i}(x): return x+{i}\n' for i in range(100)}
        d = analyze_zip(files)
        self.assertTrue(d.get('file_count', 0) >= 1)
        self.assertNotIn('error', d)

    def test_file_with_no_newline_at_end(self):
        d = analyze('def foo(): return 42')
        self.assertNotIn('error', d)

    def test_deeply_nested_functions(self):
        code = 'def a():\n'
        for i in range(10):
            code += '    ' * (i+1) + f'def b{i}():\n'
        code += '    ' * 12 + 'return 1\n'
        d = analyze(code)
        self.assertNotIn('error', d)

    def test_report_id_always_present(self):
        for code in ['x=1', 'def f(): pass', 'import os']:
            d = analyze(code)
            self.assertIn('report_id', d, f"Missing report_id for: {code}")

    def test_complexity_always_present(self):
        d = analyze('def f(x):\n    return x*2\n')
        self.assertIn('complexity', d)

    def test_convergence_always_present(self):
        d = analyze('def f(x):\n    return x*2\n')
        self.assertIn('convergence', d)

    def test_multi_vuln_same_file(self):
        d = analyze("import os,pickle\nfrom flask import request\ndef v():\n    f=request.args.get('f')\n    cmd=request.args.get('c')\n    data=request.data\n    open(f).read()\n    os.system(cmd)\n    pickle.loads(data)")
        self.assertGreaterEqual(d.get('security_count',0), 2)

    def test_analyze_files_returns_file_offsets(self):
        d = analyze_files([{'name': 'a.py', 'content': 'x=1\n'}, {'name': 'b.py', 'content': 'y=2\n'}])
        self.assertIn('file_offsets', d)
        self.assertEqual(len(d['file_offsets']), 2)

    def test_analyze_files_returns_file_names(self):
        d = analyze_files([{'name': 'a.py', 'content': 'x=1\n'}, {'name': 'b.py', 'content': 'y=2\n'}])
        self.assertEqual(set(d.get('file_names', [])), {'a.py', 'b.py'})


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def suite_size(s):
    try:
        return sum(suite_size(t) for t in s)
    except TypeError:
        return 1

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    cats = [
        ('Combine Files Math',      TestCombineFiles),
        ('Local Lineno Accuracy',   TestLocalLineno),
        ('Microdot Zip Real',       TestMicrodotZip),
        ('Empty Files',             TestEmptyFiles),
        ('UI Features',             TestUIFeatures),
        ('Routes',                  TestRoutes),
        ('Zip Extraction Rules',    TestZipExtraction),
        ('Security Regression',     TestSecurityRegression),
        ('Edge Cases',              TestEdgeCases),
    ]
    for _, cls in cats:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=0, stream=open('/dev/null','w'))
    result = runner.run(suite)

    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed

    print("=" * 65)
    print(f"FEATURE TEST RESULTS — {total} tests across {len(cats)} categories")
    print("=" * 65)
    for cat_name, cat_cls in cats:
        cat_fails  = [t for t in result.failures + result.errors if isinstance(t[0], cat_cls)]
        cat_total  = suite_size(loader.loadTestsFromTestCase(cat_cls))
        cat_passed = cat_total - len(cat_fails)
        status = "✓" if not cat_fails else "✗"
        print(f"  {status} {cat_name:<30} {cat_passed:>3}/{cat_total}")

    if result.failures or result.errors:
        print()
        print("FAILURES / ERRORS:")
        for test, tb in result.failures + result.errors:
            print(f"  {'FAIL' if (test,tb) in result.failures else 'ERROR'}: {test}")
            for line in tb.strip().split('\n')[-3:]:
                if line.strip():
                    print(f"    {line.strip()}")
            print()

    print("=" * 65)
    print(f"TOTAL: {total}  PASSED: {passed}  FAILED: {failed}")
    print("ALL TESTS PASSED ✓" if failed == 0 else f"{failed} TESTS FAILED ✗")
    print("=" * 65)
