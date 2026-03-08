"""
app.py — Infinity × Fugue Unified Engine Web Interface
"""

import concurrent.futures
import io
import zipfile
from flask import Flask, request, jsonify, render_template_string
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)
engine = MetaCodeEngine.get_instance()

ANALYZE_TIMEOUT  = 15   # single paste/file
MULTI_TIMEOUT    = 90   # multiple .py files
ZIP_TIMEOUT      = 120  # zip extraction + analysis


@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    execute = data.get('execute', False)
    program_name = data.get('name', 'program')
    if not code:
        return jsonify({'error': 'No code provided'}), 400
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(engine.orchestrate,
                               source_code=code,
                               program_name=program_name,
                               execute=execute)
            report = future.result(timeout=ANALYZE_TIMEOUT)
    except concurrent.futures.TimeoutError:
        return jsonify({
            'error': f'Analysis timed out after {ANALYZE_TIMEOUT}s. '
                     f'Code is too complex — try a smaller section.'
        }), 408
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500
    return jsonify(_serialize_report(report))


@app.route('/api/compare', methods=['POST'])
def compare():
    data = request.get_json(silent=True) or {}
    code_a = data.get('code_a', '')
    code_b = data.get('code_b', '')
    if not code_a or not code_b:
        return jsonify({'error': 'Both code_a and code_b are required'}), 400
    return jsonify(engine.compare(code_a, code_b))


@app.route('/api/analyze_files', methods=['POST'])
def analyze_files():
    """Receive multiple .py files as JSON array {files:[{name,content},...]}"""
    data = request.get_json(silent=True) or {}
    files = data.get('files', [])
    if not files:
        return jsonify({'error': 'No files provided'}), 400
    # Concatenate all files with clear separators
    combined, offsets = _combine_files(files)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(engine.orchestrate,
                               source_code=combined,
                               program_name='multi-file',
                               execute=False)
            report = future.result(timeout=MULTI_TIMEOUT)
    except concurrent.futures.TimeoutError:
        return jsonify({'error': f'Analysis timed out after {MULTI_TIMEOUT}s — too many/large files.'}), 408
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500
    result = _serialize_report(report, offsets)
    result['file_count'] = len(files)
    result['file_names'] = [f.get('name','?') for f in files]
    result['files'] = files
    result['file_offsets'] = offsets
    return jsonify(result)


@app.route('/api/analyze_zip', methods=['POST'])
def analyze_zip():
    """Receive a zip file upload, extract all .py files and analyze together."""
    uploaded = request.files.get('zip')
    if not uploaded:
        return jsonify({'error': 'No zip file uploaded'}), 400
    fname = uploaded.filename or ''
    if not fname.lower().endswith('.zip'):
        return jsonify({'error': 'File must be a .zip'}), 400
    try:
        z = zipfile.ZipFile(io.BytesIO(uploaded.read()))
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid or corrupted zip file'}), 400
    files = []
    for entry in z.namelist():
        # Normalise separators (Windows zips use backslash)
        name = entry.replace('\\', '/').strip()  # normalise paths
        # Must end in .py (case-insensitive)
        if not name.lower().endswith('.py'):
            continue
        # Skip hidden dirs, __pycache__, node_modules, venv, .git
        parts = [p for p in name.split('/') if p]
        skip_dirs = {'__pycache__', 'node_modules', '.git', 'venv',
                     '.venv', 'env', '.env', 'dist', 'build', 'eggs',
                     '.eggs', 'htmlcov', '.tox', '.mypy_cache'}
        if any(p.startswith('.') or p in skip_dirs for p in parts[:-1]):
            continue
        # Skip test/migration noise files unless they are the only files
        try:
            raw = z.open(entry).read()
            src = raw.decode('utf-8', errors='ignore').strip()
            if src is not None:  # include empty __init__.py etc.
                files.append({'name': name, 'content': src})
        except Exception:
            continue
    if not files:
        # Provide diagnostic: list what WAS in the zip
        all_names = z.namelist()[:20]
        return jsonify({
            'error': 'No Python files found in zip. '
                     f'Zip contains: {", ".join(all_names[:10])}'
                     + (' ...' if len(all_names) > 10 else '')
        }), 400
    combined, offsets = _combine_files(files)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(engine.orchestrate,
                               source_code=combined,
                               program_name='zip-upload',
                               execute=False)
            report = future.result(timeout=ZIP_TIMEOUT)
    except concurrent.futures.TimeoutError:
        return jsonify({'error': f'Analysis timed out after {ZIP_TIMEOUT}s — project is very large.'}), 408
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500
    result = _serialize_report(report, offsets)
    result['file_count'] = len(files)
    result['file_names'] = [f['name'] for f in files]
    result['files'] = files
    result['file_offsets'] = offsets
    return jsonify(result)


def _combine_files(files: list):
    """Join files with headers. Returns (combined_str, file_offsets).
    file_offsets = [{name, start_line, end_line}, ...] (1-based)
    """
    parts = []
    offsets = []
    current_line = 1
    for f in files:
        name = f.get('name', 'unknown.py')
        src  = f.get('content', '')
        header = "# === FILE: " + name + " ==="
        block  = header + "\n" + src
        line_count = block.count('\n') + 1
        offsets.append({
            'name':       name,
            'start_line': current_line,
            'end_line':   current_line + line_count - 1,
        })
        parts.append(block)
        current_line += line_count + 1  # +1: one blank separator line between files
    return "\n\n".join(parts), offsets


def _file_for_line(lineno: int, offsets: list) -> str:
    """Return the filename that contains the given line number."""
    if not offsets or lineno is None:
        return ''
    for o in offsets:
        if o['start_line'] <= lineno <= o['end_line']:
            return o['name'].split('/')[-1]  # basename only
    return 


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'engine': 'Infinity x Fugue Unified Analysis Engine',
        'run_count': engine._run_count,
        'history_quality_runs': len(engine._history_quality),
        'history_security_runs': len(engine._history_security),
    })


@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)


def _serialize_report(report, file_offsets=None) -> dict:
    security = []
    for f in report.security_findings:
        source_file = _file_for_line(f.lineno, file_offsets) if file_offsets else ''
        # Local line = lineno relative to that file's first line (for highlighting)
        local_lineno = f.lineno
        if file_offsets and f.lineno:
            for o in file_offsets:
                if o['start_line'] <= f.lineno <= o['end_line']:
                    local_lineno = f.lineno - o['start_line']  # header is start_line; content starts at start_line+1
                    break
        security.append({
            'vuln_type': f.vuln_type,
            'severity': f.severity,
            'path': f.path,
            'sink': f.sink,
            'reason': f.reason,
            'fix': f.fix,
            'lineno': f.lineno,
            'local_lineno': local_lineno,
            'source_file': source_file,
            'exploitability': f.exploitability,
            'exploit_reason': f.exploit_reason,
            'halstead_weight': f.halstead_weight,
        })
    resolution = []
    for r in report.resolution_predictions:
        resolution.append({
            'issue': r.get('issue', ''),
            'suggestion': r.get('suggestion', ''),
            'convergence': r.get('convergence', False),
            'sticky': r.get('sticky', False),
        })
    return {
        'report_id': report.report_id,
        'is_clean': report.is_clean,
        'security_findings': security,
        'security_count': len(security),
        'structural_issues': report.issues,
        'structural_count': len(report.issues),
        'complexity': report.complexity_metrics,
        'structure': report.structural_analysis,
        'convergence': report.convergence,
        'resolution': resolution,
        'fingerprint': list(report.structural_fingerprint) if report.structural_fingerprint else [],
        'execution': report.execution_result,
    }


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Infinity x Fugue</title>
<!-- LinkedIn / OpenGraph Preview -->
<meta property="og:title" content="Infinity Fugue Engine — Interactive AI System">
<meta property="og:description" content="A self-evolving computational intelligence engine. Click to launch and interact live.">
<meta property="og:image" content="https://raw.githubusercontent.com/KnottNefarious/meta-code-engine/main/pictures/Assets/ezgif-751459536f1e2012.gif">
<meta property="og:url" content="https://unified-engine--KnottNefarious.replit.app">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<!-- PWA -->
<link rel="manifest" href="/static/manifest.json">
<link rel="icon" href="/static/favicon.ico">
<meta name="theme-color" content="#0d1b2a">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Inf×Fugue">
<link rel="apple-touch-icon" href="/static/icon-192.png">
<!-- CodeMirror -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/theme/dracula.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1b2a;color:#e8eaf0;min-height:100vh}
header{background:linear-gradient(135deg,#0d1b2a,#1b3a5c);border-bottom:2px solid #2e75b6;padding:18px 28px;display:flex;align-items:center;gap:14px}
header .clef{font-size:38px;line-height:1}header{position:relative}#install-btn{display:none;margin-left:auto;background:#1b5090;border:1px solid #2e75b6;border-radius:6px;color:#90c8f0;font-size:11px;font-weight:700;line-height:1.3;padding:7px 11px;text-align:center;cursor:pointer;white-space:pre-wrap;min-width:62px;letter-spacing:.02em;transition:background .15s}#install-btn:hover{background:#2e75b6;color:#fff}
header h1{font-size:20px;font-weight:700;color:#90c8f0}
header p{font-size:12px;color:#6a8faf;margin-top:2px}
.layout{display:grid;grid-template-columns:1fr 1fr;height:calc(100vh - 80px);transition:grid-template-columns .25s ease}.layout.results-collapsed{grid-template-columns:1fr 34px}
.panel{display:flex;flex-direction:column;overflow:hidden}.results-collapsed .panel:last-child #results{display:none}.results-collapsed .panel:last-child .panel-header{writing-mode:vertical-rl;text-orientation:mixed;justify-content:center;padding:10px 0;cursor:pointer;border-bottom:none;border-left:1px solid #1e3a5c}.results-collapsed .panel:last-child .panel-header #collapse-btn{transform:rotate(180deg)}
.panel-header{background:#112233;border-bottom:1px solid #1e3a5c;padding:9px 14px;font-size:11px;font-weight:600;color:#6a8faf;letter-spacing:.08em;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between}
/* ── Code editor ── */
.file-tabs{display:none;overflow-x:auto;white-space:nowrap;background:#0a1520;border-bottom:1px solid #1e3a5c;border-right:1px solid #1e3a5c;flex-shrink:0;scrollbar-width:none}
.file-tabs::-webkit-scrollbar{display:none}
.file-tab{display:inline-block;padding:6px 13px;font-size:11px;color:#4a7a9a;cursor:pointer;border-right:1px solid #1a2e42;border-bottom:2px solid transparent;white-space:nowrap;user-select:none}
.file-tab.active{color:#90c8f0;border-bottom-color:#2e75b6;background:#0d1b2a}
.editor-wrap{flex:1;min-height:0;overflow:hidden;border-right:1px solid #1e3a5c;background:#0a141f;position:relative}
/* CodeMirror overrides — match app dark theme */
.CodeMirror{height:100%;font-family:'Fira Code','Courier New',monospace!important;font-size:13px!important;line-height:1.6!important;background:#0a141f!important;color:#c8ddef!important}
.CodeMirror-gutters{background:#0d1f30!important;border-right:1px solid #1a2e42!important;min-width:42px}
.CodeMirror-linenumber{color:#3a6a8a!important;padding:0 6px 0 0!important}
.CodeMirror-scroll{padding-bottom:0!important}
.CodeMirror-cursor{border-left:2px solid #90c8f0!important}
.CodeMirror-selected{background:#1e3a5c!important}
.CodeMirror-focused .CodeMirror-selected{background:#1e3a5c!important}
.cm-highlight-line{background:#1a3a1a!important}
/* Hide the underlying textarea CodeMirror wraps */
#code-input{display:none}
/* ── Buttons ── */
.btn-row{padding:9px 14px;background:#0d1b2a;border-top:1px solid #1e3a5c;border-right:1px solid #1e3a5c;display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.btn{padding:7px 18px;border:none;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}
.btn-primary{background:#1b5090;color:#fff}.btn-primary:hover{background:#2e75b6}
.btn-secondary{background:#1e3a5c;color:#90c8f0}.btn-secondary:hover{background:#253d5c}
.btn-upload{background:#1a3a1a;color:#4caf7c;border:1px solid #2a5c2a}.btn-upload:hover{background:#1f4a1f}
#file-input{display:none}
#file-label{padding:4px 14px;font-size:10px;color:#3a5a6a;border-right:1px solid #1e3a5c;background:#0d1b2a;min-height:18px}
/* ── Results ── */
#results{flex:1;overflow-y:auto;background:#0d1b2a;padding:14px}
.clean-badge{background:#0f3320;border:1px solid #1a5c38;border-radius:6px;padding:11px 14px;color:#4caf7c;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:7px}
.section-title{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6a8faf;margin:14px 0 7px;padding-bottom:4px;border-bottom:1px solid #1e3a5c}
/* ── Individual finding (flat mode, <=3) ── */
.finding{background:#1a0c0c;border:1px solid #5c1a1a;border-radius:5px;padding:11px;margin-bottom:7px;font-size:12px}
.finding.CRITICAL{border-color:#8b0000;background:#1e0808}
.finding.HIGH{border-color:#7a2a00;background:#1a1000}
.finding.MEDIUM{border-color:#4a3a00;background:#14120a}
.finding-header{display:flex;align-items:center;gap:7px;margin-bottom:7px}
.sev{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;letter-spacing:.06em}
.sev.CRITICAL{background:#8b0000;color:#ffcccc}
.sev.HIGH{background:#7a2a00;color:#ffd9b3}
.sev.MEDIUM{background:#4a3a00;color:#fff0a0}
.sev.LOW{background:#1a3a1a;color:#a0f0a0}
.vuln-type{font-weight:700;color:#ff8080;font-size:13px}
.finding-line{font-size:10px;color:#6a8faf;margin-left:auto}
.path-row{font-family:monospace;font-size:11px;color:#4a8fbf;margin-bottom:3px}
.detail{font-size:11px;color:#8fa8bf;margin-top:3px}
.fix-row{font-size:11px;color:#4caf7c;margin-top:3px;background:#0a1f0f;padding:5px 7px;border-radius:3px}
.finding[onclick]{cursor:pointer}
.finding[onclick]:hover{border-color:#2e75b6!important;background:#0d1e30!important;transform:translateX(2px);transition:all .12s}
/* ── Collapsible group (>3 findings) ── */
.group{margin-bottom:7px;border-radius:5px;overflow:hidden;border:1px solid #2a3a4a}
.group-header{display:flex;align-items:center;gap:8px;padding:9px 12px;cursor:pointer;background:#0f1e2e;user-select:none;transition:background .15s}
.group-header:hover{background:#142030}
.group-arrow{font-size:10px;color:#4a7a9a;transition:transform .2s;display:inline-block;width:12px}
.group-arrow.open{transform:rotate(90deg)}
.group-sev{font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.06em}
.group-sev.CRITICAL{background:#8b0000;color:#ffcccc}
.group-sev.HIGH{background:#7a2a00;color:#ffd9b3}
.group-sev.MEDIUM{background:#4a3a00;color:#fff0a0}
.group-sev.LOW{background:#1a3a1a;color:#a0f0a0}
.group-name{font-size:12px;font-weight:700;color:#ff8080}
.group-count{margin-left:auto;font-size:11px;color:#4a7a9a;background:#112233;padding:1px 8px;border-radius:10px}
.group-body{display:none;padding:8px}
.group-body.open{display:block}
.group-body .finding{margin-bottom:6px}
.group-body .finding:last-child{margin-bottom:0}
/* ── Structural issues ── */
.issue{background:#111a22;border-left:3px solid #2e75b6;padding:7px 11px;margin-bottom:5px;border-radius:0 4px 4px 0;font-size:12px;color:#a0bfd0}
.issue.error{border-color:#c0392b}.issue.warning{border-color:#e67e22}
/* ── Metrics ── */
.metric-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:7px}
.metric-card{background:#112233;border:1px solid #1e3a5c;border-radius:4px;padding:9px 11px}
.metric-label{font-size:9px;color:#6a8faf;text-transform:uppercase;letter-spacing:.06em}
.metric-value{font-size:17px;font-weight:700;color:#90c8f0;margin-top:1px}
.metric-sub{font-size:9px;color:#4a7a9a;margin-top:1px}
.fp{font-family:monospace;font-size:10px;color:#3a6a8a;word-break:break-all}
.loading{text-align:center;padding:40px;color:#4a7a9a}
.spinner{width:26px;height:26px;border:3px solid #1e3a5c;border-top-color:#2e75b6;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 10px}
@keyframes spin{to{transform:rotate(360deg)}}
.compare-layout{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:7px}
.compare-layout textarea{background:#0a141f;color:#c8ddef;border:1px solid #1e3a5c;border-radius:4px;padding:9px;font-family:monospace;font-size:12px;height:130px;resize:vertical;width:100%}
.sim-score{font-size:34px;font-weight:700;text-align:center;padding:14px 0}
.sim-score.isomorphic{color:#4caf7c}.sim-score.similar{color:#f0c040}.sim-score.divergent{color:#ff6060}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:#0a141f}
::-webkit-scrollbar-thumb{background:#1e3a5c;border-radius:3px}
</style>
</head>
<body>
<header>
  <span class="clef">&#119070;</span>
  <div>
    <h1>Infinity &times; Fugue &mdash; Unified Code Analysis Engine</h1>
    <p>G(x) &bull; Dissonance &bull; Transposition &bull; Resolution &bull; K(x)</p>
  </div>
  <button id="install-btn" onclick="installApp()" title="Install as app">Install&#10;App Now</button>
</header>
<div class="layout">
  <div class="panel">
    <div class="panel-header">
      <span>Source Code</span>
      <span id="line-count" style="color:#3a5a6a">1 line</span>
    </div>
    <div id="file-tabs" class="file-tabs"></div>
    <div class="editor-wrap">
      <textarea id="code-input"></textarea>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary" onclick="runAnalyze()">&#9654; Analyze</button>
      <button class="btn btn-secondary" onclick="showCompare()">&#8644; Compare</button>
      <button class="btn btn-secondary" onclick="clearAll()">&#10005; Clear</button>
      <button class="btn btn-upload" onclick="document.getElementById('file-input').click()">&#128196; .py Files</button>
      <button class="btn btn-upload" onclick="document.getElementById('zip-input').click()">&#128230; ZIP</button>
      <input type="file" id="file-input" accept=".py,.txt" multiple onchange="loadFiles(event)">
      <input type="file" id="zip-input" accept=".zip,application/zip,application/x-zip-compressed" onchange="loadZip(event)">
      <button class="btn btn-upload" onclick="downloadFiles()" title="Download current file(s)">&#11015; Save</button>
      <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:#6a8faf;margin-left:auto">
        <input type="checkbox" id="run-exec"> Execute
      </label>
    </div>
    <div id="file-label"></div>
  </div>
  <div class="panel">
    <div class="panel-header" onclick="toggleResults(event)">
      <span id="results-label">Analysis Results</span>
      <span id="run-badge" style="color:#3a5a6a"></span>
      <button id="collapse-btn" title="Collapse/expand results"
        style="background:none;border:none;color:#6a8faf;font-size:14px;cursor:pointer;padding:0 0 0 8px;line-height:1;flex-shrink:0"
        onclick="event.stopPropagation();toggleResults(event)">&#8249;</button>
    </div>
    <div id="results">
      <div style="padding:40px;text-align:center;color:#3a5a6a">
        <div style="font-size:30px;margin-bottom:10px">&#119070;</div>
        <div>Write, paste, or upload a .py file, then click Analyze.</div>
      </div>
    </div>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/python/python.min.js"></script>
<script>
const codeEl    = document.getElementById('code-input'); // used only for CM init below
var   editor;  // CodeMirror instance — initialized at bottom
const resultsEl = document.getElementById('results');
const runBadge  = document.getElementById('run-badge');
const lineCount = document.getElementById('line-count');
const fileLabel = document.getElementById('file-label');

/* ── PWA Install ───────────────────────────────────────────── */
var _installPrompt = null;
var _installBtn    = document.getElementById('install-btn');

// Android/Chrome/Edge: capture the prompt before browser discards it
window.addEventListener('beforeinstallprompt', function(e){
  e.preventDefault();
  _installPrompt = e;
  _installBtn.style.display = 'block';
});

// Hide button once installed
window.addEventListener('appinstalled', function(){
  _installBtn.style.display = 'none';
  _installPrompt = null;
});

// iOS Safari has no beforeinstallprompt — detect and show manual tip instead
(function(){
  var isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
  var isStandalone = window.navigator.standalone === true;
  if(isIOS && !isStandalone){
    _installBtn.style.display = 'block';
    _installBtn.title = 'Tap Share → Add to Home Screen';
  }
})();

function installApp(){
  if(_installPrompt){
    _installPrompt.prompt();
    _installPrompt.userChoice.then(function(result){
      if(result.outcome === 'accepted') _installBtn.style.display = 'none';
      _installPrompt = null;
    });
  } else {
    // iOS: show instructions in a small alert
    alert('On iPhone/iPad:\n1. Tap the Share button (box with arrow)\n2. Tap \"Add to Home Screen\"\n3. Tap Add');
  }
}

/* ── Line numbers ─────────────────────────────────────────── */
// updateLineNums() removed — CodeMirror handles gutter automatically
// Tab, scroll, and input listeners removed — handled by CodeMirror
// editor.on('change',...) set up during initialization at bottom of script

/* ── File tabs ────────────────────────────────────────────── */
var _loadedFiles = [];   // [{name, content}, ...]
var _activeTab   = 0;
var _zipFile     = null;
var _zipName     = 'archive';  // original zip filename stem

function buildTabs(files){
  _loadedFiles = files;
  _activeTab   = 0;
  var tabBar = document.getElementById('file-tabs');
  if(files.length <= 1){ tabBar.style.display='none'; return; }
  tabBar.style.display='block';
  tabBar.innerHTML = '';
  files.forEach(function(f, i){
    var tab = document.createElement('span');
    tab.className = 'file-tab' + (i===0 ? ' active' : '');
    tab.textContent = f.name.split('/').pop();
    tab.title = f.name;
    tab.onclick = function(){ switchTab(i); };
    tabBar.appendChild(tab);
  });
}

function switchTab(i){
  _activeTab = i;
  var tabs = document.querySelectorAll('.file-tab');
  tabs.forEach(function(t,j){ t.className = 'file-tab' + (j===i?' active':''); });
  editor.setValue(_loadedFiles[i].content);
  // Scroll the tab bar so the active tab is visible
  var activeTab = tabs[i];
  if(activeTab){
    var tabBar = document.getElementById('file-tabs');
    var tabLeft  = activeTab.offsetLeft;
    var tabRight = tabLeft + activeTab.offsetWidth;
    if(tabLeft < tabBar.scrollLeft){
      tabBar.scrollLeft = tabLeft - 8;
    } else if(tabRight > tabBar.scrollLeft + tabBar.clientWidth){
      tabBar.scrollLeft = tabRight - tabBar.clientWidth + 8;
    }
  }
}

/* ── File upload — multiple .py files ────────────────────── */
function loadFiles(event){
  var files = Array.from(event.target.files).filter(function(f){
    return f.name.endsWith('.py') || f.name.endsWith('.txt');
  });
  event.target.value = '';
  if(!files.length){ setLabel('Please choose .py or .txt files','#ff6060'); return; }
  _zipFile = null;
  setLabel('Reading ' + files.length + ' file' + (files.length>1?'s':'') + '...','#90c8f0');
  readAllFiles(files).then(function(objs){
    buildTabs(objs);
    editor.setValue(objs[0].content);
    if(objs.length === 1){
      setLabel('Loaded: ' + objs[0].name, '#4caf7c');
    } else {
      setLabel(objs.length + ' files loaded \u2014 click Analyze', '#4caf7c');
    }
  }).catch(function(err){
    setLabel('Error reading files: ' + err.message, '#ff6060');
  });
}

/* ── ZIP upload ───────────────────────────────────────────── */
function loadZip(event){
  var file = event.target.files[0];
  event.target.value = '';
  if(!file){ return; }
  if(!file.name.toLowerCase().endsWith('.zip')){
    setLabel('Please choose a .zip file','#ff6060'); return;
  }
  _zipFile = file;
  _zipName = file.name.replace(/\.zip$/i, '');
  _loadedFiles = [];
  buildTabs([]);
  editor.setValue('# ZIP: ' + file.name + '\n# Click Analyze to scan all .py files inside.');
  setLabel('ZIP ready: ' + file.name + ' \u2014 click Analyze','#90c8f0');
}

/* ── Read multiple files ──────────────────────────────────── */
function readAllFiles(files){
  return Promise.all(files.map(function(f){
    return new Promise(function(res,rej){
      var r = new FileReader();
      r.onload  = function(e){ res({name:f.name, content:e.target.result}); };
      r.onerror = function(){ rej(new Error('Failed to read '+f.name)); };
      r.readAsText(f);
    });
  }));
}

function setLabel(msg,color){
  fileLabel.textContent = msg;
  fileLabel.style.color = color||'#4caf7c';
}

/* ── Resolve combined-file line → {file, localLine} ─────── */
function resolveStructLine(combinedLine){
  var offsets = window._fileOffsets || [];
  if(!offsets.length) return { file: '', localLine: combinedLine };
  // First pass: exact match
  for(var i=0; i<offsets.length; i++){
    var o = offsets[i];
    if(combinedLine >= o.start_line && combinedLine <= o.end_line){
      var local = combinedLine - o.start_line;
      return { file: o.name.split('/').pop(), localLine: local };
    }
  }
  // Second pass: line falls in a gap between files — use the previous file
  var best = offsets[0];
  for(var j=0; j<offsets.length; j++){
    if(offsets[j].start_line <= combinedLine) best = offsets[j];
    else break;
  }
  var local = combinedLine - best.start_line;
  return { file: best.name.split('/').pop(), localLine: local };
}

/* ── Event delegation for structural issue clicks ────────── */
resultsEl.addEventListener('click', function(e){
  var el = e.target.closest('.js-struct-issue');
  if(!el) return;
  var combinedLine = parseInt(el.dataset.lineno||'0');
  if(combinedLine <= 0) return;
  var resolved = resolveStructLine(combinedLine);
  goToFinding(resolved.file, resolved.localLine);
});

/* ── Collapse / Expand Results Panel ─────────────────────── */
function toggleResults(e){
  var layout = document.querySelector('.layout');
  var btn    = document.getElementById('collapse-btn');
  var label  = document.getElementById('results-label');
  var collapsed = layout.classList.toggle('results-collapsed');
  // When collapsed: ‹ becomes › and header is the only visible thing (rotated by CSS)
  btn.innerHTML   = collapsed ? '&#8250;' : '&#8249;';
  btn.title       = collapsed ? 'Expand results' : 'Collapse results';
  label.style.display = collapsed ? 'none' : '';
}

/* ── Download / Save ─────────────────────────────────────── */
// Track how many times each base name has been downloaded for (1),(2)... suffixes
var _downloadCounts = {};

function _nextDownloadName(base, ext){
  var key = (base + ext).toLowerCase();
  _downloadCounts[key] = (_downloadCounts[key] || 0) + 1;
  var n = _downloadCounts[key];
  return n === 1 ? base + ext : base + '(' + n + ')' + ext;
}

function downloadFiles(){
  // Sync current editor content before saving
  if(_loadedFiles.length > 0 && _activeTab < _loadedFiles.length){
    _loadedFiles[_activeTab].content = editor.getValue();
  }

  if(_loadedFiles.length <= 1){
    // Single file — prompt for rename, then download as .py
    var defaultName = (_loadedFiles.length === 1
      ? _loadedFiles[0].name.split('/').pop()
      : 'code.py');
    var chosen = window.prompt('Save file as:', defaultName);
    if(chosen === null) return;  // user cancelled
    chosen = chosen.trim() || defaultName;
    // Ensure .py extension
    if(!chosen.match(/\.[a-zA-Z]+$/)) chosen += '.py';
    var fileContent = _loadedFiles.length === 1 ? _loadedFiles[0].content : editor.getValue();
    _triggerDownload(chosen, fileContent);
  } else {
    // Multiple files — build a zip preserving original folder structure
    if(typeof JSZip === 'undefined'){
      var s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
      s.onload = function(){ downloadFiles(); };
      document.head.appendChild(s);
      return;
    }
    var zip = new JSZip();
    _loadedFiles.forEach(function(f){
      // Preserve full relative path so folders are intact in the zip
      zip.file(f.name, f.content);
    });
    var baseName = _zipName || 'archive';
    var zipFilename = _nextDownloadName(baseName, '.zip');
    zip.generateAsync({type:'blob'}).then(function(blob){
      _triggerDownload(zipFilename, blob);
    });
  }
}

function _triggerDownload(filename, data){
  // data can be string or Blob
  var blob = (data instanceof Blob) ? data : new Blob([data], {type: 'application/octet-stream'});
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function(){ URL.revokeObjectURL(url); }, 2000);
}

/* ── Clear ────────────────────────────────────────────────── */
function clearAll(){
  editor.setValue('');
  resultsEl.innerHTML=''; runBadge.textContent='';
  fileLabel.textContent=''; fileLabel.style.color='#3a5a6a';
  _loadedFiles=[]; _activeTab=0; _zipFile=null; _zipName='archive';
  buildTabs([]);
}

/* ── Collapsible group toggle ─────────────────────────────── */
function toggleGroup(id){
  const body  = document.getElementById('gb-'+id);
  const arrow = document.getElementById('ga-'+id);
  const open  = body.classList.toggle('open');
  arrow.classList.toggle('open', open);
}

/* ── Navigate to finding in editor ──────────────────────── */
function goToFinding(filename, lineno){
  // Switch to correct file tab if multi-file
  var didSwitch = false;
  if(filename && _loadedFiles.length > 1){
    var idx = _loadedFiles.findIndex(function(f){
      return f.name.split('/').pop() === filename || f.name === filename;
    });
    if(idx >= 0 && idx !== _activeTab){ switchTab(idx); didSwitch = true; }
  }
  if(!lineno) return;
  // Defer highlight slightly if we just switched tabs so content has settled
  setTimeout(function(){
    _highlightLine(lineno);
  }, didSwitch ? 30 : 0);
}

function _highlightLine(lineno){
  var lineCount = editor.lineCount();
  if(lineno < 1 || lineno > lineCount) return;
  var lineText = editor.getLine(lineno - 1) || '';
  var indent   = lineText.length - lineText.trimStart().length;
  // Select from first non-whitespace to end of line
  editor.setSelection(
    {line: lineno-1, ch: indent},
    {line: lineno-1, ch: Math.max(indent+1, lineText.length)}
  );
  // Scroll the line to the center of the visible editor
  editor.scrollIntoView({line: lineno-1, ch: 0}, editor.getScrollInfo().clientHeight / 2);
  editor.focus();
  // Flash the line background green to draw the eye
  editor.addLineClass(lineno-1, 'background', 'cm-highlight-line');
  setTimeout(function(){
    editor.removeLineClass(lineno-1, 'background', 'cm-highlight-line');
  }, 700);
}

/* ── Navigate to a file by name (used by banner) ─────────── */
function goToFile(filename){
  if(!filename || _loadedFiles.length <= 1) return;
  var idx = _loadedFiles.findIndex(function(f){
    return f.name.split('/').pop() === filename || f.name === filename;
  });
  if(idx >= 0) switchTab(idx);
}

/* ── Build a single finding card ─────────────────────────── */
function findingCard(f){
  const sev    = f.severity||'MEDIUM';
  const hasLoc = f.lineno || f.source_file;
  // locParts defined in locRow below
  // Show local_lineno (per-file) in the card, not the combined-file lineno
  const displayLine = (f.local_lineno !== undefined ? f.local_lineno : f.lineno) || 0;
  const locParts2 = [
    f.source_file ? '<span style="color:#90c8f0;font-weight:600">'+esc(f.source_file)+'</span>' : '',
    displayLine   ? '<span style="color:#6a9fcf">line '+displayLine+'</span>' : ''
  ].filter(Boolean);
  const locRow = hasLoc
    ? '<div style="margin-top:4px;font-size:11px;line-height:1.8">'
      + (locParts2[0] ? locParts2[0]+'<br>' : '')
      + (locParts2[1] ? locParts2[1] : '')
      + '<span style="font-size:10px;color:#2e75b6;margin-left:6px">&#8599; jump to line</span>'
      +'</div>'
    : '';
  // Use local_lineno (relative to the individual file) for in-editor highlight
  const jumpLine = (f.local_lineno !== undefined ? f.local_lineno : f.lineno) || 0;
  const clickable = hasLoc
    ? 'style="cursor:pointer" onclick="goToFinding(\''+esc(f.source_file||'')+'\','+jumpLine+')"'
      +' title="Click to jump to this line in the editor"'
    : '';
  return '<div class="finding '+sev+'" '+clickable+'>'
    +'<div class="finding-header">'
      +'<span class="sev '+sev+'">'+esc(sev)+'</span>'
      +' <span class="vuln-type">'+esc(f.vuln_type)+'</span>'
    +'</div>'
    +locRow
    +'<div class="path-row">'+(f.path||[]).map(esc).join(' &rarr; ')+' &rarr; <strong>'+esc(f.sink)+'</strong></div>'
    +'<div class="detail">'+esc(f.reason)+'</div>'
    +'<div class="fix-row" style="background:#0a2015;border:1px solid #1a4a2a;border-radius:4px;padding:7px 10px;margin-top:6px;font-size:11px;line-height:1.5">'
      +'<span style="color:#4caf7c;font-weight:700">&#10003; Fix:</span> '+esc(f.fix)
    +'</div>'
    +(f.halstead_weight>1.0?'<div style="font-size:10px;color:#f0c040;margin-top:4px">&#9888; Complexity weight '+f.halstead_weight+'&times; &mdash; high-risk function</div>':'')
    +'</div>';
}

/* ── Render security findings ─────────────────────────────── */
function renderSecurityFindings(findings){
  if(!findings||findings.length===0) return '';

  let html = `<div class="section-title">Security Dissonance &mdash; ${findings.length} finding${findings.length===1?'':'s'}</div>`;

  // 3 or fewer — show flat, no collapsing needed
  if(findings.length <= 3){
    for(const f of findings) html += findingCard(f);
    return html;
  }

  // 4 or more — group by vuln_type, sorted by severity
  const sevOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3};
  const groups = {};
  for(const f of findings){
    const key = f.vuln_type || 'Unknown';
    if(!groups[key]) groups[key] = {sev: f.severity||'MEDIUM', findings:[]};
    groups[key].findings.push(f);
  }
  // Sort groups by severity
  const sorted = Object.entries(groups).sort((a,b)=>{
    return (sevOrder[a[1].sev]||9) - (sevOrder[b[1].sev]||9);
  });

  let groupId = 0;
  for(const [vuln_type, group] of sorted){
    const id      = groupId++;
    const sev     = group.sev;
    const count   = group.findings.length;
    // CRITICAL groups auto-open, everything else starts closed
    const isOpen  = sev === 'CRITICAL';
    const bodyClass = isOpen ? 'group-body open' : 'group-body';
    const arrowClass = isOpen ? 'group-arrow open' : 'group-arrow';

    html += `<div class="group">
      <div class="group-header" onclick="toggleGroup(${id})">
        <span id="ga-${id}" class="${arrowClass}">&#9658;</span>
        <span class="group-sev ${sev}">${esc(sev)}</span>
        <span class="group-name">${esc(vuln_type)}</span>
        <span class="group-count">${count}</span>
      </div>
      <div id="gb-${id}" class="${bodyClass}">`;
    for(const f of group.findings) html += findingCard(f);
    html += `</div></div>`;
  }
  return html;
}

/* ── Compare ──────────────────────────────────────────────── */
function showCompare(){
  const backBtn = window._lastResultsHTML
    ? '<button class="btn btn-secondary" onclick="restoreResults()" style="margin-bottom:10px;width:100%">&#8592; Back to Analysis Results</button>'
    : '';
  resultsEl.innerHTML = backBtn + `
    <div class="section-title">Structural Transposition &mdash; F : C &cong; D</div>
    <div class="compare-layout">
      <textarea id="cmp-a" placeholder="Program A..."></textarea>
      <textarea id="cmp-b" placeholder="Program B..."></textarea>
    </div>
    <button class="btn btn-primary" onclick="runCompare()" style="width:100%">&#8644; Compare Structures</button>
    <div id="cmp-result" style="margin-top:10px"></div>`;
}

function restoreResults(){
  if(window._lastResultsHTML){
    resultsEl.innerHTML = window._lastResultsHTML;
  }
}

async function runCompare(){
  const a=document.getElementById('cmp-a').value;
  const b=document.getElementById('cmp-b').value;
  if(!a||!b)return;
  const r=await fetch('/api/compare',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code_a:a,code_b:b})}).then(r=>r.json());
  const score=Math.round((r.overall_similarity||0)*100);
  const cls=r.verdict==='isomorphic'?'isomorphic':score>50?'similar':'divergent';
  document.getElementById('cmp-result').innerHTML=`
    <div class="sim-score ${cls}">${score}%</div>
    <div style="text-align:center;color:#6a8faf;font-size:12px;margin-bottom:10px">
      Verdict: <strong style="color:#90c8f0">${esc(r.verdict||'unknown')}</strong>
    </div>
    <div class="metric-grid">
      <div class="metric-card"><div class="metric-label">Type Similarity</div>
        <div class="metric-value">${Math.round((r.type_similarity||0)*100)}%</div></div>
      <div class="metric-card"><div class="metric-label">Depth Similarity</div>
        <div class="metric-value">${Math.round((r.depth_similarity||0)*100)}%</div></div>
    </div>`;
}

/* ── Analyze ──────────────────────────────────────────────── */
async function runAnalyze(){
  const execute=document.getElementById('run-exec').checked;
  resultsEl.innerHTML='<div class="loading"><div class="spinner"></div>Analyzing&hellip;</div>';
  let data;
  try{
    if(_zipFile){
      const fd=new FormData();
      fd.append('zip',_zipFile);
      setLabel('Uploading & extracting ZIP…','#90c8f0');
      const resp=await fetch('/api/analyze_zip',{method:'POST',body:fd});
      data=await resp.json();
      _zipFile=null;
      // Build tabs from returned file contents
      if(data.files&&data.files.length){
        buildTabs(data.files);
        editor.setValue(data.files[0].content);
      }
    } else if(_loadedFiles.length>1){
      const resp=await fetch('/api/analyze_files',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({files:_loadedFiles})});
      data=await resp.json();
      // Rebuild tabs (files already loaded but refresh state)
      if(data.files&&data.files.length){ buildTabs(data.files); }
    } else {
      const code=editor.getValue().trim();
      if(!code){
        resultsEl.innerHTML='<div style="color:#4a7a9a;padding:20px;text-align:center">Paste code or upload a file first.</div>';
        return;
      }
      const resp=await fetch('/api/analyze',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({code,execute})});
      data=await resp.json();
    }
  }catch(e){
    resultsEl.innerHTML='<div style="color:#ff6060;padding:14px">Server error: '+e.message+'</div>';
    return;
  }
  if(data.error){
    resultsEl.innerHTML=`<div style="background:#1a0c0c;border:1px solid #5c1a1a;border-radius:5px;padding:14px;color:#ff8080;font-size:13px"><strong>&#9888; ${esc(data.error)}</strong></div>`;
    return;
  }
  const conv=data.convergence||{};
  runBadge.textContent='Run #'+(conv.run_number||'?');
  // Store file offsets for structural issue navigation
  window._fileOffsets = data.file_offsets || [];
  window._lastResultsHTML = null;  // will be set after render
  let banner='';
  if(data.file_count>1){
    // Build vertical list of clickable filenames
    var chips=(data.file_names||[]).map(function(n){
      var base=n.split('/').pop();
      return '<div style="padding:2px 0">'
            +'<span style="color:#4caf7c;text-decoration:underline;cursor:pointer" '
            +'onclick="goToFile(\''+base+'\')" title="Switch to '+base+'">'+esc(base)+'</span>'
            +'</div>';
    }).join('');
    banner='<div style="background:#0f2233;border:1px solid #1e5c3a;border-radius:5px;padding:8px 12px;font-size:11px;margin-bottom:10px">'
           +'<div style="color:#6a9fcf;margin-bottom:4px">&#128230; Analyzed '+data.file_count+' files:</div>'
           +chips+'</div>';
  }
  const rendered = banner + renderReport(data);
  resultsEl.innerHTML = rendered;
  window._lastResultsHTML = rendered;
}

/* ── Render full report ───────────────────────────────────── */
function renderReport(d){
  let html='';

  if(d.is_clean){
    html+=`<div class="clean-badge">&#10003; No issues found &mdash; structurally and security-clean</div>`;
  }

  // Security findings — flat if <=3, grouped if >3
  html += renderSecurityFindings(d.security_findings);

  // Structural issues — clickable to jump to line
  // Uses data-lineno (combined) + resolveStructLine for navigation
  // Displays LOCAL line number and filename to user (not combined)
  if(d.structural_issues&&d.structural_issues.length>0){
    html+='<div class="section-title">Structural Dissonance &mdash; '+d.structural_count+' issue'+(d.structural_count===1?'':'s')+'</div>';
    var multiFile = window._fileOffsets && window._fileOffsets.length > 1;
    for(var si=0;si<d.structural_issues.length;si++){
      var iss=d.structural_issues[si];
      var cls=iss.includes('Error')?'error':'warning';
      var lineMatch=iss.match(/\bline\s+(\d+)/i);
      var combinedNo=lineMatch?parseInt(lineMatch[1]):0;
      if(combinedNo>0){
        var res=resolveStructLine(combinedNo);
        // Replace combined line number with local line in display text
        var displayIss=iss.replace(/\(line \d+\)/,'(line '+res.localLine+')');
        // Prefix filename if multi-file
        var filePrefix = (multiFile && res.file)
          ? '<span style="color:#90c8f0;font-weight:600;margin-right:6px">'+esc(res.file)+'</span>'
          : '';
        html+='<div class="issue '+cls+' js-struct-issue" data-lineno="'+combinedNo+'" style="cursor:pointer">'
             +'<div style="display:flex;justify-content:space-between;align-items:flex-start">'
             +'<span>'+filePrefix+esc(displayIss)+'</span>'
             +'<span style="flex-shrink:0;margin-left:8px;font-size:10px;color:#2e75b6;white-space:nowrap">&#8599; line '+res.localLine+'</span>'
             +'</div></div>';
      } else {
        html+='<div class="issue '+cls+'">'+esc(iss)+'</div>';
      }
    }
  }

  // Math metrics
  const cplx=d.complexity||{};
  const hal=cplx.halstead||{};
  const struct=d.structure||{};
  const conv=d.convergence||{};
  const qConv=conv.quality||{};
  const sConv=conv.security||{};
  if(Object.keys(cplx).length>0){
    html+=`<div class="section-title">Mathematical Analysis</div>
    <div class="metric-grid">
      <div class="metric-card"><div class="metric-label">G(x) Value</div>
        <div class="metric-value">${struct.polynomial_value??'&mdash;'}</div>
        <div class="metric-sub">Generating function</div></div>
      <div class="metric-card"><div class="metric-label">K(x) Normalized</div>
        <div class="metric-value">${typeof cplx.normalized_ratio==='number'?cplx.normalized_ratio.toFixed(3):'&mdash;'}</div>
        <div class="metric-sub">Kolmogorov complexity</div></div>
      <div class="metric-card"><div class="metric-label">Halstead Volume</div>
        <div class="metric-value">${typeof hal.volume==='number'?hal.volume.toFixed(1):'&mdash;'}</div>
        <div class="metric-sub">Information content (bits)</div></div>
      <div class="metric-card"><div class="metric-label">Estimated Bugs</div>
        <div class="metric-value">${typeof hal.estimated_bugs==='number'?hal.estimated_bugs.toFixed(2):'&mdash;'}</div>
        <div class="metric-sub">Halstead B = V/3000</div></div>
    </div>`;
    html+=`<div class="section-title">Resolution &mdash; Banach Convergence</div>
    <div class="metric-grid">
      <div class="metric-card"><div class="metric-label">Quality Converging</div>
        <div class="metric-value">${qConv.is_converging===null?'&mdash;':qConv.is_converging?'&#10003; Yes':'&#9888; No'}</div>
        <div class="metric-sub">Toward zero issues</div></div>
      <div class="metric-card"><div class="metric-label">Security Converging</div>
        <div class="metric-value">${sConv.is_converging===null?'&mdash;':sConv.is_converging===true?'&#10003; Yes':sConv.is_converging===false?'&#9888; No':'&mdash;'}</div>
        <div class="metric-sub">Toward zero findings</div></div>
    </div>`;
    const seq=qConv.sequence||conv.sequence||[];
    if(seq.length>1){
      html+=`<div style="font-size:10px;color:#6a8faf;margin-bottom:3px">Jaccard distance sequence:</div><div style="display:flex;gap:3px;flex-wrap:wrap;margin-bottom:7px">`;
      for(const v of seq)html+=`<span style="background:#112233;padding:2px 7px;border-radius:3px;font-family:monospace;font-size:11px">${v.toFixed(3)}</span>`;
      html+=`</div>`;
    }
    if(d.fingerprint&&d.fingerprint.length>0){
      html+=`<div class="section-title">Structural Fingerprint</div><div class="fp">${esc(JSON.stringify(d.fingerprint))}</div>`;
    }
  }
  return html||'<div style="color:#4a7a9a;padding:14px;text-align:center">Analysis complete.</div>';
}

function esc(s){
  if(s===undefined||s===null)return'';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── CodeMirror initialization ───────────────────────────── */
editor = CodeMirror.fromTextArea(codeEl, {
  mode:        'python',
  theme:       'dracula',
  lineNumbers: true,
  tabSize:     4,
  indentUnit:  4,
  indentWithTabs: false,
  lineWrapping: false,
  autofocus:   false,
  inputStyle:  'contenteditable',  // best cross-device experience
  extraKeys: {
    'Tab': function(cm){
      if(cm.somethingSelected()){
        cm.indentSelection('add');
      } else {
        cm.replaceSelection('    ');
      }
    }
  }
});

// Keep lineCount header in sync + clear fileLabel + sync back to _loadedFiles
editor.on('change', function(){
  var n = editor.lineCount();
  lineCount.textContent = n + (n===1 ? ' line' : ' lines');
  fileLabel.textContent = '';
  // Keep current tab content in sync so switching tabs doesn't lose edits
  if(_loadedFiles.length > 0 && _activeTab < _loadedFiles.length){
    _loadedFiles[_activeTab].content = editor.getValue();
  }
});

// Set initial line count
lineCount.textContent = '1 line';
</script>
</body>
</html>"""

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
