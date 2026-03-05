<div align="center">

```.   
 
          .%%@@@@@@%
         #%%@@@@@%@%%%+
         +%#::@@@@@@@@@@%%-
         %%=  =@@@@@@@@@%%%
         %@%%@@@@@@@@@@@%%%
                .@@@@@%%%
     .%%%@@@@@@@@@@@@@@@@@@@@@% -%%%%%.
    +%@@@@@@@@@@@@@@@@@@@@@@%@@ -@@@%%%+
   %%@@@@@@@@@@@%@@@@@@@@@@@@= -@@@@%%%.
   %@@@@@@@@@@@@@@@@@@@@@@@%:  %@@@%%%%.
   -%@@@@@@@@%+-             :#@@@@@@%%%.
   %@@@@@%%= :+@%@@@@@@@@@@@@@@@@@@@%%%.
   %@@@@@@- -%@@@@@@@@@@@@@@@@@@@@@@%%%.
   +@@@%@@- %@@@@@@@@@@@@@%@@@@@@%%%@@+
  :%%%%%- %@@@@@@@@@@@@@@@@@@%@%%%%.
%%@%@@@@:    
    %%@@@@@@@@@@@@%%@%
    %@@@@@@@@@@@+  *@%
    -%@%@@@@@@@@#::#%+
      =%%%@%%@%%%%%%
        %@@@@@@@%

```       

</div>

# infinity-fugue-engine  
🫀🫀🫀🫀🫀🫀🫀🫀🫀🫀🫀🫀

 Python code analysis engine (mobile friendly) built on Mathematical Contrapuntalism — security + quality dissonance detection using generating functions, Banach convergence, and path-sensitive taint analysis.

# Infinity × Fugue — Unified Code Analysis Engine 🎼

> *"meta-mathamatical language that an AI can use to talk about math while it's doing/using math."*

  Python code analysis engine built entirely on a single meta-mathematical framework — **Mathematical Contrapuntalism**. Not a linter with math added on top. The math *is* the analysis.

---

## Live Demo 💾

<table><tr>
  <td><img src="https://raw.githubusercontent.com/KnottNefarious/meta-code-engine/main/pictures/Assets/Screenshot_20260301-044352~4.png" width="150"></td>
  <td><img src="https://raw.githubusercontent.com/KnottNefarious/meta-code-engine/main/pictures/Assets/unnamed.jpg" width="150"></td>
</tr></table>


👉 Deploy to Replit and visit the web interface to analyze code instantly.

[![Launch Infinity-Fugue-Engine](https://raw.githubusercontent.com/KnottNefarious/meta-code-engine/1cc58596e1d5844b047ec95799cb75061296a8e3/pictures/Assets/ezgif-751459536f1e2012.gif)](https://unified-engine--KnottNefarious.replit.app)

---

## What It Does

Analyzes Python code in two dimensions simultaneously: 🐍⛎

**Security Dissonance** — finds vulnerabilities by proving that Γ cannot establish "input at sink S is safe":🧮
- SQL Injection 
- Command Injection
- Path Traversal
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Unsafe Deserialization
- Insecure Direct Object Reference (IDOR)
- Missing Authorization

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

| Move          | Math.                                         | Engine Stage                                          |
|---------------|-----------------------------------------------|-------------------------------------------------------|
| Subject       | G(x) = Σ aₙxⁿ                                 | SubjectExtractor — reads structural shape, not values |
| Dissonance.   | Γ ⊢ φ ⟺ ¬(Γ ∪ {¬φ} consistent).              | DissonanceDetector + PathSensitiveTaintAnalyzer.      |
| Transposition | F : C ≅ D                                    | TranspositionFinder — structural DNA matching.        |
| Resolution    | lim \|Sₙ − L\| < ε                            | ResolutionPredictor — Banach fixed-point convergence  |
| Compression.  | K(x) = min{\|p\| : U(p) = x}                  | KolmogorovComplexity + HalsteadMetrics                |

Security analysis is not a sixth thing. It is **Dissonance at full depth** — the same formal structure, applied to a harder class of logical contradiction: the security contract a program makes with its users.

A taint analysis and Python security scanner providing static analysis powered by formal mathematics.
---

## Quick Start

### Replit
1. Import this repository into Replit
2. Click **Run** — Replit reads `.replit` and starts automatically
3. Open the web interface in the Replit browser pane

### Local
```bash
git clone https://github.com/YOUR_USERNAME/infinity-fugue-engine
cd infinity-fugue-engine
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

---

## API

### `POST /api/analyze`
```json
{ "code": "def view():\n    uid = request.args.get('id')\n    cursor.execute('SELECT * FROM t WHERE id = ' + uid)" }
```
Returns a full report: security findings, structural issues, K(x), Halstead, G(x), convergence sequence, fix predictions.

### `POST /api/compare`
```json
{ "code_a": "...", "code_b": "..." }
```
Returns structural transposition analysis: type similarity, depth similarity, call-graph similarity, verdict (isomorphic / similar / divergent).

### `GET /api/health`
Returns engine status, run count, convergence history length.
---

## Architecture

meta_code/
├── taint.py          Path-sensitive taint analysis (CFG × TaintState)
├── sinks.py          Security sink definitions — all 8 vulnerability types
├── meta_engine.py    7-stage orchestrator (singleton for convergence tracking)
├── resolution.py     Banach fixed-point convergence, Jaccard distance
├── core.py           Data structures: Finding, Issue, DissonanceReport
├── subject.py        G(x) generating function, structural fingerprint
├── dissonance.py     CFG + ScopeTree + ShadowAnalyzer
├── compression.py    Normalized K(x) + Halstead metrics
├── transposition.py  Structural comparison: type + depth + call-graph
└── execution.py      Sandboxed runtime verification


### Singleton Design
The engine is instantiated once at server start, not inside request handlers. This is what makes Banach convergence meaningful — the history of every analysis run accumulates across the server's lifetime, and the Jaccard distance sequence is real.

### Path-Sensitive Taint
Taint analysis uses a CFG × TaintState product construction. At each point in the program, taint state is carried path by path:
- abort() and raise are path terminators — they correctly propagate authorization guards
- BinOp returns taint from either operand (fixes the most common injection blind spot)
- All function bodies are analyzed unconditionally — Flask @app.route functions included

---

## Tests 2️⃣➕2️⃣🟰❔

bash
python tests/test_suite.py


93 tests across 10 categories:
|Type of test.              |number of type|✓|
|---------------------------|--------------|-|
|- Taint Sources            |(7 tests)     |✓|
|- Taint Propagation        |(8 tests).    |✓|
|- Sink Detection.          |(18 tests)    |✓|
|- False Positives.         |(8 tests).    |✓|
|- Path Sensitivity         |(4 tests).    |✓|
|- Inter-Procedural         |(4 tests).    |✓|
|- Structural Quality.      |(11 tests).   |✓|
|- Mathematical             |(11 tests).   |✓|
|- Pipeline / Integration 3 |(9 tests).    |✓|
|- Edge Cases               |(13 tests).   |✓|

All 93 pass.🤯

---

## Mathematical Foundations 🧠

- **Generating Functions** — Flajolet & Sedgewick, *Analytic Combinatorics* (2009)
- **Formal Logic Γ ⊢ φ** — Sequent calculus; Gentzen (1935)
- **Kolmogorov Complexity** — Kolmogorov (1965), Chaitin (1966)
- **Halstead Metrics** — Maurice Halstead, *Elements of Software Science* (1977)
- **Banach Fixed-Point Theorem** — Stefan Banach (1922)
- **Jaccard Distance** — proper metric; reflexive, symmetric, triangle inequality holds
- **Categorical Functors F: C ≅ D** — Mac Lane & Eilenberg (1945)
- **Dataflow Analysis** — Kildall (1973); CFG × TaintState product construction

---

## License 🪪

MIT
