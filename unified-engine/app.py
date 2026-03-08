"""
app.py — Infinity × Fugue Unified Engine Web Interface
"""

import concurrent.futures
from flask import Flask, request, jsonify, render_template_string
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)
engine = MetaCodeEngine.get_instance()

ANALYZE_TIMEOUT  = 15   # seconds before giving up


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


def _serialize_report(report) -> dict:
    security = []
    for f in report.security_findings:
        security.append({
            'vuln_type': f.vuln_type,
            'severity': f.severity,
            'path': f.path,
            'sink': f.sink,
            'reason': f.reason,
            'fix': f.fix,
            'lineno': f.lineno,
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
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1b2a;color:#e8eaf0;min-height:100vh}
header{background:linear-gradient(135deg,#0d1b2a,#1b3a5c);border-bottom:2px solid #2e75b6;padding:18px 28px;display:flex;align-items:center;gap:14px}
header .clef{font-size:38px;line-height:1}
header h1{font-size:20px;font-weight:700;color:#90c8f0}
header p{font-size:12px;color:#6a8faf;margin-top:2px}
.layout{display:grid;grid-template-columns:1fr 1fr;height:calc(100vh - 80px)}
.panel{display:flex;flex-direction:column}
.panel-header{background:#112233;border-bottom:1px solid #1e3a5c;padding:9px 14px;font-size:11px;font-weight:600;color:#6a8faf;letter-spacing:.08em;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between}
/* ── Code editor ── */
.editor-wrap{flex:1;display:flex;overflow:hidden;border-right:1px solid #1e3a5c;background:#0a141f}
#line-nums{width:42px;min-width:42px;background:#0d1f30;border-right:1px solid #1a2e42;padding:14px 6px 14px 0;font-family:'Fira Code','Courier New',monospace;font-size:13px;line-height:1.6;color:#3a6a8a;text-align:right;overflow:hidden;user-select:none;white-space:pre}
#code-input{flex:1;background:#0a141f;color:#c8ddef;font-family:'Fira Code','Courier New',monospace;font-size:13px;line-height:1.6;padding:14px 14px 14px 10px;border:none;outline:none;resize:none;overflow-y:auto;white-space:pre;tab-size:4}
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
</header>
<div class="layout">
  <div class="panel">
    <div class="panel-header">
      <span>Source Code</span>
      <span id="line-count" style="color:#3a5a6a">1 line</span>
    </div>
    <div class="editor-wrap">
      <div id="line-nums">1</div>
      <textarea id="code-input" spellcheck="false" placeholder="# Paste or type Python code here, or tap Upload File..."></textarea>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary" onclick="runAnalyze()">&#9654; Analyze</button>
      <button class="btn btn-secondary" onclick="showCompare()">&#8644; Compare</button>
      <button class="btn btn-secondary" onclick="clearAll()">&#10005; Clear</button>
      <button class="btn btn-upload" onclick="document.getElementById('file-input').click()">&#128196; Upload File</button>
      <input type="file" id="file-input" accept=".py,.txt" onchange="loadFile(event)">
      <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:#6a8faf;margin-left:auto">
        <input type="checkbox" id="run-exec"> Execute
      </label>
    </div>
    <div id="file-label"></div>
  </div>
  <div class="panel">
    <div class="panel-header">
      <span>Analysis Results</span>
      <span id="run-badge" style="color:#3a5a6a"></span>
    </div>
    <div id="results">
      <div style="padding:40px;text-align:center;color:#3a5a6a">
        <div style="font-size:30px;margin-bottom:10px">&#119070;</div>
        <div>Write, paste, or upload a .py file, then click Analyze.</div>
      </div>
    </div>
  </div>
</div>
<script>
const codeEl    = document.getElementById('code-input');
const lineNums  = document.getElementById('line-nums');
const resultsEl = document.getElementById('results');
const runBadge  = document.getElementById('run-badge');
const lineCount = document.getElementById('line-count');
const fileLabel = document.getElementById('file-label');

/* ── Line numbers ─────────────────────────────────────────── */
function updateLineNums(){
  const count = Math.max(1, codeEl.value.split('\n').length);
  let nums = '';
  for(let i=1;i<=count;i++) nums += i + '\n';
  lineNums.textContent = nums;
  lineCount.textContent = count + (count===1?' line':' lines');
}
codeEl.addEventListener('scroll', () => { lineNums.scrollTop = codeEl.scrollTop; });
codeEl.addEventListener('input', () => { updateLineNums(); fileLabel.textContent=''; });
codeEl.addEventListener('keydown', (e) => {
  if(e.key==='Tab'){
    e.preventDefault();
    const s=codeEl.selectionStart, en=codeEl.selectionEnd;
    codeEl.value=codeEl.value.substring(0,s)+'    '+codeEl.value.substring(en);
    codeEl.selectionStart=codeEl.selectionEnd=s+4;
    updateLineNums();
  }
});

/* ── File upload ──────────────────────────────────────────── */
function loadFile(event){
  const file=event.target.files[0];
  if(!file)return;
  if(!file.name.endsWith('.py')&&!file.name.endsWith('.txt')){
    fileLabel.textContent='Please choose a .py or .txt file';
    fileLabel.style.color='#ff6060';
    return;
  }
  const reader=new FileReader();
  reader.onload=function(e){
    codeEl.value=e.target.result;
    updateLineNums();
    fileLabel.textContent='Loaded: '+file.name;
    fileLabel.style.color='#4caf7c';
  };
  reader.readAsText(file);
  event.target.value='';
}

/* ── Clear ────────────────────────────────────────────────── */
function clearAll(){
  codeEl.value=''; updateLineNums();
  resultsEl.innerHTML=''; runBadge.textContent=''; fileLabel.textContent='';
}

/* ── Collapsible group toggle ─────────────────────────────── */
function toggleGroup(id){
  const body  = document.getElementById('gb-'+id);
  const arrow = document.getElementById('ga-'+id);
  const open  = body.classList.toggle('open');
  arrow.classList.toggle('open', open);
}

/* ── Build a single finding card ─────────────────────────── */
function findingCard(f){
  const sev=f.severity||'MEDIUM';
  return `<div class="finding ${sev}">
    <div class="finding-header">
      <span class="sev ${sev}">${esc(sev)}</span>
      <span class="vuln-type">${esc(f.vuln_type)}</span>
      ${f.lineno?`<span class="finding-line">line ${f.lineno}</span>`:''}
    </div>
    <div class="path-row">${(f.path||[]).map(esc).join(' &rarr; ')} &rarr; <strong>${esc(f.sink)}</strong></div>
    <div class="detail">${esc(f.reason)}</div>
    <div class="fix-row">&#10003; Fix: ${esc(f.fix)}</div>
    ${f.halstead_weight>1.0?`<div style="font-size:10px;color:#f0c040;margin-top:3px">&#9888; Complexity weight ${f.halstead_weight}&times; &mdash; high-risk function</div>`:''}
  </div>`;
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
  resultsEl.innerHTML=`
    <div class="section-title">Structural Transposition &mdash; F : C &cong; D</div>
    <div class="compare-layout">
      <textarea id="cmp-a" placeholder="Program A..."></textarea>
      <textarea id="cmp-b" placeholder="Program B..."></textarea>
    </div>
    <button class="btn btn-primary" onclick="runCompare()" style="width:100%">&#8644; Compare Structures</button>
    <div id="cmp-result" style="margin-top:10px"></div>`;
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
  const code=codeEl.value.trim();
  if(!code)return;
  const execute=document.getElementById('run-exec').checked;
  resultsEl.innerHTML='<div class="loading"><div class="spinner"></div>Analyzing&hellip;</div>';
  let data;
  try{
    const resp=await fetch('/api/analyze',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({code,execute})});
    data=await resp.json();
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
  resultsEl.innerHTML=renderReport(data);
}

/* ── Render full report ───────────────────────────────────── */
function renderReport(d){
  let html='';

  if(d.is_clean){
    html+=`<div class="clean-badge">&#10003; No issues found &mdash; structurally and security-clean</div>`;
  }

  // Security findings — flat if <=3, grouped if >3
  html += renderSecurityFindings(d.security_findings);

  // Structural issues
  if(d.structural_issues&&d.structural_issues.length>0){
    html+=`<div class="section-title">Structural Dissonance &mdash; ${d.structural_count} issue${d.structural_count===1?'':'s'}</div>`;
    for(const iss of d.structural_issues){
      const cls=iss.includes('Error')?'error':'warning';
      html+=`<div class="issue ${cls}">${esc(iss)}</div>`;
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

updateLineNums();
</script>
</body>
</html>"""

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
