# Infinity × Fugue — Unified Code Analysis Engine

> *"A language that an AI can use to talk about math while it's doing math."*

A Python code analysis engine built entirely on a single meta-mathematical framework — **Mathematical Contrapuntalism**. Not a linter with math added on top. The math *is* the analysis.

## Live Demo

**[https://unified-engine--KnottNefarious.replit.app](https://unified-engine--KnottNefarious.replit.app)**

---

## What It Does

Analyzes Python code in two dimensions simultaneously:

**Security Dissonance** — finds vulnerabilities by proving that Γ cannot establish "input at sink S is safe":
- SQL Injection
- Command Injection
- Path Traversal (read, write, and `with open(...)` forms)
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Unsafe Deserialization
- Insecure Direct Object Reference (IDOR)
- Missing Authorization
- Code Injection (eval/exec)

**Structural Dissonance** — finds code quality issues by proving logical contradictions:
- Unreachable code (after return, raise, constant-false conditions)
- Unused variables (scope-aware, closure-aware)
- Wasted assignments (overwritten before first read)

**Mathematical Analysis** — every run produces:
- G(x) = Σ aₙxⁿ — depth-indexed generating function (structural fingerprint)
- K(x) normalized — Kolmogorov complexity via compression
- Halstead metrics — Volume, Difficulty, Effort, Estimated Bugs
- Banach convergence — Jaccard distance tracking across runs
- Structural transposition — isomorphism detection between programs

---

## The Framework

Each analysis stage maps exactly to one of the five original reasoning moves:

| Move | Math | Engine Stage |
|------|------|--------------|
| Subject | G(x) = Σ aₙxⁿ | SubjectExtractor — reads structural shape, not values |
| Dissonance | Γ ⊢ φ ⟺ ¬(Γ ∪ {¬φ} consistent) | DissonanceDetector + PathSensitiveTaintAnalyzer |
| Transposition | F : C ≅ D | TranspositionFinder — structural DNA matching |
| Resolution | lim \|Sₙ − L\| < ε | ResolutionPredictor — Banach fixed-point convergence |
| Compression | K(x) = min{\|p\| : U(p) = x} | KolmogorovComplexity + HalsteadMetrics |

Security analysis is not a sixth thing. It is **Dissonance at full depth** — the same formal structure, applied to a harder class of logical contradiction: the security contract a program makes with its users.

---

## Quick Start

### Replit
1. Import this repository into Replit
2. Click **Run** — Replit reads `.replit` and starts automatically
3. Open the web interface in the Replit browser pane

### Local
```bash
git clone https://github.com/KnottNefarious/infinity-fugue-engine
cd infinity-fugue-engine/unified-engine
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

---

## UI Features

### Editor
- **CodeMirror 5** — full Python syntax highlighting with Dracula theme
- Line numbers, Tab-key indent, proper mobile keyboard support
- Click any finding → jumps to that exact line in the correct file, highlights it green

### Multi-File & ZIP Support
- Upload multiple `.py` files at once — each gets its own tab
- Upload a `.zip` — all Python files extracted, analyzed as a unified project
- Finding line numbers always show the **local** line within each file, never the combined offset
- Click a filename in the results banner to jump directly to that file's tab

### Download
- **Single file** — prompts to rename, downloads as `.py`
- **Multiple files / ZIP** — reconstructs the original zip faithfully: edited `.py` files swapped in, every other file (config, markdown, images, etc.) preserved exactly as uploaded
- Downloaded zips named after the original (`microdot-1.zip` → `microdot-1(2).zip`)

### Other
- **Collapsible results panel** — tap `‹` to collapse to a slim strip for full-width editor
- **Compare panel** — structural isomorphism analysis between two programs, with back button
- **PWA install** — "Install App Now" button in header; installs as standalone app on Android/Chrome/Edge; iOS shows Share → Add to Home Screen instructions
- **Execute mode** — checkbox to run code in sandboxed environment

---

## API

### `POST /api/analyze`
Single file analysis (15s timeout).
```json
{ "code": "def view():\n    uid = request.args.get('id')\n    cursor.execute('SELECT * FROM t WHERE id = ' + uid)" }
```
Returns: `report_id`, `security_findings`, `structural_issues`, `security_count`, `structural_count`, `complexity`, `convergence`, `halstead`, `gx`.

Each security finding includes: `vuln_type`, `severity`, `lineno`, `local_lineno`, `source_file`, `reason`, `fix`, `exploitability`, `exploit_reason`, `halstead_weight`.

### `POST /api/analyze_files`
Multiple `.py` files (90s timeout).
```json
{ "files": [{ "name": "routes.py", "content": "..." }, { "name": "models.py", "content": "..." }] }
```
Returns full report plus `files`, `file_offsets`, `file_names`, `file_count`.

### `POST /api/analyze_zip`
ZIP upload (120s timeout). Multipart form with `zip` field.

Excludes: `__pycache__`, `.git`, `venv`, `.venv`, `node_modules`, `dist`, `build`.
Includes: empty `__init__.py` files.

Returns same shape as `analyze_files`.

### `POST /api/compare`
```json
{ "code_a": "...", "code_b": "..." }
```
Returns: `overall_similarity`, `type_similarity`, `depth_similarity`, `callgraph_similarity`, `verdict`.

### `GET /api/health`
Returns engine status, run count, convergence history length.

---

## Architecture

```
unified-engine/
├── app.py                Main Flask app — all routes, file combination, serialization, full UI
├── requirements.txt
├── .replit
├── replit.nix
├── static/
│   ├── manifest.json     PWA manifest
│   ├── favicon.ico
│   ├── icon-192.png
│   └── icon-512.png
├── meta_code/
│   ├── taint.py          Path-sensitive taint analysis (CFG × TaintState), with-statement support
│   ├── sinks.py          Security sink definitions — all 9 vulnerability types
│   ├── meta_engine.py    7-stage orchestrator (singleton for convergence tracking)
│   ├── resolution.py     Banach fixed-point convergence, Jaccard distance
│   ├── core.py           Data structures: Finding, Issue, DissonanceReport
│   ├── subject.py        G(x) generating function, structural fingerprint
│   ├── dissonance.py     CFG + ScopeTree + ShadowAnalyzer
│   ├── compression.py    Normalized K(x) + Halstead metrics
│   ├── transposition.py  Structural comparison: type + depth + call-graph
│   └── execution.py      Sandboxed runtime verification
└── tests/
    ├── test_suite.py      93 core tests
    ├── test_realworld.py  244 real-world tests
    └── test_features.py   109 feature tests
```

### Key Design Decisions

**File combination** — multi-file and ZIP analysis combines all `.py` files with `# === FILE: path ===` headers. Offsets tracked so every finding reports `local_lineno` (line within its own file). Offset math uses `current_line += line_count + 1` — verified zero-discrepancy across all 89 files in the microdot test zip.

**Singleton engine** — instantiated once at server start so Banach convergence history accumulates across the server lifetime.

**Path-sensitive taint** — CFG × TaintState product construction:
- `abort()` and `raise` are path terminators — correctly propagates authorization guards
- `BinOp` returns taint from either operand — fixes the most common injection blind spot
- `with open(f) as h:` — taint propagates into the `as` variable and body
- All function bodies analyzed unconditionally — Flask `@app.route` functions included

---

## Tests

```bash
python tests/test_suite.py       # 93 tests
python tests/test_realworld.py   # 244 tests
python tests/test_features.py    # 109 tests
```

**Total: 446 tests, 446 passing.**

### test_suite.py (93)
Taint Sources · Taint Propagation · Sink Detection · False Positives · Path Sensitivity · Inter-Procedural · Structural Quality · Mathematical · Pipeline/Integration · Edge Cases

### test_realworld.py (244)
- Single File (100): all 9 vuln types, false-positive checks
- Multi-File (82): cross-file taint, offset accuracy, local lineno correctness
- ZIP Upload (62): real zip extraction, folder structure, 89-file microdot project

### test_features.py (109)
- Combine Files Math (6): offset zero-discrepancy across file counts
- Local Lineno Accuracy (5): per-file line numbers for multi-file and zip
- Microdot Zip Real (11): 89 files, offsets, local lines, structural issues
- Empty Files (2): empty `__init__.py` counted correctly
- UI Features (39): CodeMirror, collapse panel, install button, download, PWA, back button
- Routes (12): all endpoints, error responses, method restrictions
- Zip Extraction Rules (10): exclusions, corrupt zips, edge cases
- Security Regression (10): all 9 vuln types, false-positive rejection
- Edge Cases (14): unicode, large zips, concurrent requests, response structure

---

<details>
<summary><strong>How It Compares to Standard Linters & Security Scanners</strong></summary>

&nbsp;

The table below compares Infinity × Fugue against the most widely used Python static analysis tools. Each tool was designed with a different primary goal — this comparison reflects those differences honestly.

| Capability | Inf × Fugue | Pylint | Flake8 | Bandit | Semgrep | SonarQube |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Security — SQL Injection** | ✅ taint | ❌ | ❌ | ⚠️ pattern | ⚠️ pattern | ⚠️ pattern |
| **Security — Command Injection** | ✅ taint | ❌ | ❌ | ⚠️ pattern | ⚠️ pattern | ⚠️ pattern |
| **Security — Path Traversal** | ✅ taint | ❌ | ❌ | ⚠️ pattern | ⚠️ pattern | ⚠️ pattern |
| **Security — SSRF** | ✅ taint | ❌ | ❌ | ⚠️ pattern | ⚠️ pattern | ⚠️ pattern |
| **Security — Deserialization** | ✅ taint | ❌ | ❌ | ✅ | ⚠️ pattern | ⚠️ pattern |
| **Security — XSS / IDOR** | ✅ taint | ❌ | ❌ | ❌ | ⚠️ pattern | ⚠️ pattern |
| **Path-sensitive taint analysis** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (enterprise) |
| **Dataflow across functions** | ✅ | ❌ | ❌ | ❌ | ⚠️ limited | ✅ (enterprise) |
| **Unreachable code detection** | ✅ | ✅ | ⚠️ limited | ❌ | ❌ | ✅ |
| **Unused variable detection** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Structural fingerprint G(x)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Kolmogorov complexity K(x)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Halstead metrics** | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ partial |
| **Banach convergence tracking** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Structural isomorphism compare** | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ clone detect |
| **Web UI — no install needed** | ✅ | ❌ | ❌ | ❌ | ⚠️ cloud only | ⚠️ self-hosted |
| **ZIP / multi-file upload** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (CI) |
| **Per-file local line numbers** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **PEP 8 / style enforcement** | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Type checking** | ❌ | ⚠️ limited | ❌ | ❌ | ❌ | ✅ |
| **Custom rule authoring** | ❌ | ⚠️ plugins | ⚠️ plugins | ❌ | ✅ | ✅ |
| **CI/CD integration** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Import / dependency checks** | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Docstring / convention checks** | ❌ | ✅ | ⚠️ limited | ❌ | ❌ | ✅ |
| **Free / open source** | ✅ | ✅ | ✅ | ✅ | ⚠️ freemium | ⚠️ community ed. |

&nbsp;

**Key for pattern-based vs taint-based security (⚠️ vs ✅):**

Pattern-based scanners flag calls to known dangerous functions (`os.system`, `pickle.loads`, `eval`) regardless of whether the input is actually user-controlled. This produces false positives when the argument is a constant string, and false negatives when the dangerous call is indirect.

Taint-based analysis (what Infinity × Fugue uses) tracks data flow from user-controlled sources (`request.args`, `request.form`, `request.data`, etc.) through the call graph to a sink. It only fires when a real path exists from source to sink — meaning it catches injections the pattern scanners miss, and stays quiet on safe code that pattern scanners would flag.

&nbsp;

**What each tool is actually for:**

- **Flake8** — PEP 8 style enforcement. Fast, no false positives, integrates everywhere. Use it.
- **Pylint** — Comprehensive code quality. Catches logic errors, import issues, naming conventions. Slow but thorough.
- **Bandit** — Quick security scan, good for CI gates. Pattern-based so review every finding manually.
- **Mypy** — Type correctness. If your codebase uses type hints, mypy is essential.
- **Semgrep** — Security rules at scale. Best when you need custom rules for your own patterns.
- **SonarQube** — Enterprise analysis platform. Best for teams with CI/CD pipelines and long-term trend dashboards.
- **Infinity × Fugue** — Mathematical code intelligence. Path-sensitive taint analysis, structural fingerprinting, and convergence tracking. Best when you want to understand *why* code is vulnerable, not just *that* it is.

These tools are not mutually exclusive. Flake8 + Bandit + Infinity × Fugue together cover style, quick security gates, and deep taint analysis with zero overlap.

</details>

---

## Mathematical Foundations

- **Generating Functions** — Flajolet & Sedgewick, *Analytic Combinatorics* (2009)
- **Formal Logic Γ ⊢ φ** — Sequent calculus; Gentzen (1935)
- **Kolmogorov Complexity** — Kolmogorov (1965), Chaitin (1966)
- **Halstead Metrics** — Maurice Halstead, *Elements of Software Science* (1977)
- **Banach Fixed-Point Theorem** — Stefan Banach (1922)
- **Jaccard Distance** — proper metric; reflexive, symmetric, triangle inequality holds
- **Categorical Functors F: C ≅ D** — Mac Lane & Eilenberg (1945)
- **Dataflow Analysis** — Kildall (1973); CFG × TaintState product construction

---

## License

MIT
