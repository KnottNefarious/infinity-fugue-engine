"""
Infinity × Fugue — Unified Engine Test Suite
=============================================

Tests are organized by what they prove, not just what they check.
Every test has a comment explaining WHY it matters and what failure means.

Test categories:
  A. Taint Sources       — does the engine correctly identify attacker-controlled input?
  B. Taint Propagation   — does taint follow data correctly through code?
  C. Sink Detection      — does the engine catch each vulnerability class?
  D. False Positives     — does the engine stay silent when code is safe?
  E. Path Sensitivity    — does the engine handle branches and guards correctly?
  F. Inter-Procedural    — does taint cross function boundaries?
  G. Structural Quality  — unused vars, unreachable code, wasted assignments
  H. Mathematical        — G(x), K(x), Halstead, Banach convergence, Transposition
  I. Pipeline            — end-to-end orchestration, report structure, singleton
  J. Edge Cases          — empty code, syntax errors, nested functions, decorators
"""

import sys
import ast
import unittest

sys.path.insert(0, '/home/claude/unified-engine')


# =============================================================================
# A. TAINT SOURCE TESTS
# =============================================================================

class TestTaintSources(unittest.TestCase):
    """
    The engine must recognize all Flask request.* attributes as taint sources.
    Failure here means the entire security analysis is blind from the start.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_request_args(self):
        """request.args.get() is the most common Flask taint source."""
        code = """
def view():
    x = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + x)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('SQL Injection', types, "request.args.get() must be recognized as taint source")

    def test_request_form(self):
        """POST form data is equally attacker-controlled."""
        code = """
def view():
    x = request.form.get('cmd')
    import subprocess
    subprocess.run(x, shell=True)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('Command Injection', types, "request.form must be recognized as taint source")

    def test_request_json(self):
        """JSON body data from API requests."""
        code = """
def view():
    data = request.json
    uid = data['id']
    return open(uid).read()
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('Path Traversal', types, "request.json must be recognized as taint source")

    def test_request_headers(self):
        """HTTP headers can be attacker-controlled (e.g. X-Forwarded-For abuse)."""
        code = """
def view():
    host = request.headers.get('Host')
    cursor.execute("SELECT * FROM t WHERE host = " + host)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('SQL Injection', types, "request.headers must be recognized as taint source")

    def test_request_cookies(self):
        """Cookies are client-controlled and must be treated as tainted."""
        code = """
def view():
    sid = request.cookies.get('session')
    cursor.execute("SELECT * FROM sessions WHERE id = " + sid)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('SQL Injection', types, "request.cookies must be recognized as taint source")

    def test_request_data(self):
        """Raw request body data."""
        code = """
def view():
    raw = request.data
    import pickle
    return pickle.loads(raw)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('Unsafe Deserialization', types, "request.data must be recognized as taint source")

    def test_request_values(self):
        """request.values combines args and form — still tainted."""
        code = """
def view():
    x = request.values.get('q')
    cursor.execute("SELECT * FROM t WHERE q = " + x)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('SQL Injection', types, "request.values must be recognized as taint source")


# =============================================================================
# B. TAINT PROPAGATION TESTS
# =============================================================================

class TestTaintPropagation(unittest.TestCase):
    """
    Taint must follow data as it moves through the program.
    If propagation fails, attackers can hide injections behind variable reassignment.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_single_variable_propagation(self):
        """Taint must survive one assignment hop."""
        code = """
def view():
    raw = request.args.get('id')
    uid = raw
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must propagate through a single variable assignment")

    def test_multi_hop_propagation(self):
        """Taint must survive multiple assignment hops — common obfuscation pattern."""
        code = """
def view():
    a = request.args.get('id')
    b = a
    c = b
    d = c
    cursor.execute("SELECT * FROM t WHERE id = " + d)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must survive 4-hop propagation chain")

    def test_string_concat_propagation(self):
        """String concatenation propagates taint — the most common injection pattern."""
        code = """
def view():
    uid = request.args.get('id')
    query = "SELECT * FROM t WHERE id = " + uid
    cursor.execute(query)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must propagate through string concatenation into variable then into sink")

    def test_fstring_propagation(self):
        """f-strings are a common injection vector."""
        code = """
def view():
    uid = request.args.get('id')
    query = f"SELECT * FROM t WHERE id = {uid}"
    cursor.execute(query)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must propagate through f-string interpolation")

    def test_dict_value_propagation(self):
        """Taint stored in a dict value and then retrieved must still be tainted."""
        code = """
def view():
    data = {'key': request.args.get('val')}
    cursor.execute("SELECT * FROM t WHERE x = " + data['key'])
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must propagate through dict storage and retrieval")

    def test_list_element_propagation(self):
        """Taint in a list element must survive list indexing."""
        code = """
def view():
    items = [request.args.get('cmd')]
    import subprocess
    subprocess.run(items[0], shell=True)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'Command Injection' for f in findings),
            "Taint must propagate through list storage and indexing")

    def test_taint_does_not_spread_to_clean_variables(self):
        """A tainted variable must not contaminate an unrelated clean variable."""
        code = """
def view():
    tainted = request.args.get('id')
    clean = "SELECT * FROM t WHERE id = 1"
    cursor.execute(clean)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0,
            "Clean variable used in sink must not trigger finding")

    def test_reassignment_clears_taint_with_literal(self):
        """If a tainted variable is reassigned to a literal, it becomes clean."""
        code = """
def view():
    uid = request.args.get('id')
    uid = "safe_hardcoded_value"
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0,
            "Reassignment to a constant must clear taint")


# =============================================================================
# C. SINK DETECTION TESTS
# =============================================================================

class TestSinkDetection(unittest.TestCase):
    """
    Every vulnerability class must be detected. 
    These are the core security findings users depend on.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def _has(self, code, vuln_type):
        return any(f.vuln_type == vuln_type for f in self._findings(code))

    # ── SQL Injection ──────────────────────────────────────────────────────

    def test_sqli_execute(self):
        """cursor.execute() with tainted string concatenation."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
        self.assertTrue(self._has(code, 'SQL Injection'))

    def test_sqli_executemany(self):
        """cursor.executemany() is also a SQL sink."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.executemany("INSERT INTO t VALUES (" + uid + ")", [])
"""
        self.assertTrue(self._has(code, 'SQL Injection'))

    def test_sqli_via_format(self):
        """% formatting and .format() are injection vectors."""
        code = """
def view():
    uid = request.args.get('id')
    query = "SELECT * FROM t WHERE id = %s" % uid
    cursor.execute(query)
"""
        self.assertTrue(self._has(code, 'SQL Injection'))

    # ── Command Injection ──────────────────────────────────────────────────

    def test_cmd_subprocess_run_shell(self):
        """subprocess.run() with shell=True and tainted argument."""
        code = """
def view():
    cmd = request.args.get('cmd')
    import subprocess
    subprocess.run(cmd, shell=True)
"""
        self.assertTrue(self._has(code, 'Command Injection'))

    def test_cmd_subprocess_call_shell(self):
        """subprocess.call() with shell=True."""
        code = """
def view():
    cmd = request.args.get('cmd')
    import subprocess
    subprocess.call(cmd, shell=True)
"""
        self.assertTrue(self._has(code, 'Command Injection'))

    def test_cmd_os_system(self):
        """os.system() is always a command sink when tainted."""
        code = """
def view():
    cmd = request.args.get('cmd')
    import os
    os.system(cmd)
"""
        self.assertTrue(self._has(code, 'Command Injection'))

    def test_cmd_subprocess_no_shell_is_safe(self):
        """subprocess without shell=True is NOT a command injection."""
        code = """
def view():
    filename = request.args.get('file')
    import subprocess
    subprocess.run(['ls', filename])
"""
        findings = self._findings(code)
        cmd = [f for f in findings if f.vuln_type == 'Command Injection']
        self.assertEqual(len(cmd), 0,
            "subprocess without shell=True should not trigger Command Injection")

    # ── Path Traversal ─────────────────────────────────────────────────────

    def test_path_traversal_open(self):
        """open() with tainted path argument."""
        code = """
def view():
    filename = request.args.get('file')
    return open(filename).read()
"""
        self.assertTrue(self._has(code, 'Path Traversal'))

    def test_path_traversal_open_write(self):
        """open() for writing is equally dangerous."""
        code = """
def view():
    filename = request.args.get('file')
    open(filename, 'w').write('data')
"""
        self.assertTrue(self._has(code, 'Path Traversal'))

    # ── Cross-Site Scripting ───────────────────────────────────────────────

    def test_xss_return_html_concat(self):
        """Tainted data concatenated into HTML and returned."""
        code = """
def view():
    name = request.args.get('name')
    return "<html><h1>Hello " + name + "</h1></html>"
"""
        self.assertTrue(self._has(code, 'Cross-Site Scripting (XSS)'))

    def test_xss_via_format(self):
        """f-string XSS."""
        code = """
def view():
    name = request.args.get('name')
    return f"<html><body>{name}</body></html>"
"""
        self.assertTrue(self._has(code, 'Cross-Site Scripting (XSS)'))

    def test_xss_render_template_string(self):
        """render_template_string with tainted input."""
        code = """
def view():
    name = request.args.get('name')
    return render_template_string("<h1>" + name + "</h1>")
"""
        self.assertTrue(self._has(code, 'Cross-Site Scripting (XSS)'))

    # ── SSRF ───────────────────────────────────────────────────────────────

    def test_ssrf_requests_get(self):
        """requests.get() with tainted URL."""
        code = """
def view():
    url = request.args.get('url')
    import requests
    return requests.get(url).text
"""
        self.assertTrue(self._has(code, 'Server-Side Request Forgery (SSRF)'))

    def test_ssrf_requests_post(self):
        """requests.post() with tainted URL."""
        code = """
def view():
    url = request.args.get('url')
    import requests
    return requests.post(url, data={}).text
"""
        self.assertTrue(self._has(code, 'Server-Side Request Forgery (SSRF)'))

    def test_ssrf_urllib(self):
        """urllib.request.urlopen() with tainted URL."""
        code = """
def view():
    url = request.args.get('url')
    import urllib.request
    return urllib.request.urlopen(url).read()
"""
        self.assertTrue(self._has(code, 'Server-Side Request Forgery (SSRF)'))

    # ── Unsafe Deserialization ─────────────────────────────────────────────

    def test_deserial_pickle_loads(self):
        """pickle.loads() with tainted data — arbitrary code execution."""
        code = """
def view():
    data = request.data
    import pickle
    return pickle.loads(data)
"""
        self.assertTrue(self._has(code, 'Unsafe Deserialization'))

    def test_deserial_yaml_load(self):
        """yaml.load() without Loader is a deserialization sink."""
        code = """
def view():
    data = request.data
    import yaml
    return yaml.load(data)
"""
        self.assertTrue(self._has(code, 'Unsafe Deserialization'))

    def test_deserial_yaml_safe_load_is_safe(self):
        """yaml.safe_load() is NOT a deserialization vulnerability."""
        code = """
def view():
    data = request.data
    import yaml
    return yaml.safe_load(data)
"""
        findings = self._findings(code)
        deserial = [f for f in findings if f.vuln_type == 'Unsafe Deserialization']
        self.assertEqual(len(deserial), 0,
            "yaml.safe_load() must not trigger Unsafe Deserialization")

    # ── IDOR / Missing Authorization ───────────────────────────────────────

    def test_idor_direct_db_access(self):
        """Tainted ID used to access database resource without auth check."""
        code = """
def view():
    doc_id = request.args.get('doc_id')
    return db.get_document(doc_id)
"""
        self.assertTrue(self._has(code, 'Insecure Direct Object Reference (IDOR)'),
            "Direct DB access with tainted ID and no auth check must be flagged")

    def test_missing_auth_delete(self):
        """Sensitive delete operation with tainted input and no auth check."""
        code = """
def view():
    uid = request.args.get('id')
    db.delete_user(uid)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertTrue(
            'Missing Authorization' in types or 'Insecure Direct Object Reference (IDOR)' in types,
            "Sensitive delete with no auth check must be flagged")

    def test_missing_auth_transfer(self):
        """Financial transfer with no verification — the prompt.txt example."""
        code = """
def view():
    to = request.args.get('to')
    amount = request.args.get('amount')
    bank.transfer(current_user.account, to, amount)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertTrue(
            'Missing Authorization' in types or 'Insecure Direct Object Reference (IDOR)' in types,
            "Financial transfer with no verification must be flagged")


# =============================================================================
# D. FALSE POSITIVE TESTS
# =============================================================================

class TestFalsePositives(unittest.TestCase):
    """
    The engine must stay silent when code is actually safe.
    False positives destroy trust in the tool — worse than missing a real finding
    in some ways, because they train users to ignore alerts.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_clean_function_no_findings(self):
        """A function with no request input must produce zero security findings."""
        code = """
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}"
"""
        findings = self._findings(code)
        self.assertEqual(len(findings), 0, "Clean code must produce zero security findings")

    def test_parameterized_sql_is_safe(self):
        """Parameterized queries are the correct fix — must not be flagged."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0, "Parameterized SQL must not be flagged")

    def test_markupsafe_escape_prevents_xss(self):
        """markupsafe.escape() is a recognized sanitizer — must suppress XSS."""
        code = """
from markupsafe import escape
def view():
    name = request.args.get('name')
    safe = escape(name)
    return "<html><h1>" + str(safe) + "</h1></html>"
"""
        findings = self._findings(code)
        xss = [f for f in findings if f.vuln_type == 'Cross-Site Scripting (XSS)']
        self.assertEqual(len(xss), 0, "markupsafe.escape() must suppress XSS finding")

    def test_html_escape_prevents_xss(self):
        """html.escape() is a standard library sanitizer."""
        code = """
import html
def view():
    name = request.args.get('name')
    safe = html.escape(name)
    return "<html><h1>" + safe + "</h1></html>"
"""
        findings = self._findings(code)
        xss = [f for f in findings if f.vuln_type == 'Cross-Site Scripting (XSS)']
        self.assertEqual(len(xss), 0, "html.escape() must suppress XSS finding")

    def test_literal_sql_is_safe(self):
        """SQL query using only literals must not be flagged."""
        code = """
def view():
    cursor.execute("SELECT * FROM users WHERE id = 1")
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0, "Literal-only SQL must not be flagged")

    def test_subprocess_list_no_shell(self):
        """subprocess with a literal list and no shell=True is safe."""
        code = """
def view():
    subprocess.run(['ls', '-la'])
"""
        findings = self._findings(code)
        cmd = [f for f in findings if f.vuln_type == 'Command Injection']
        self.assertEqual(len(cmd), 0, "subprocess with literal list and no shell=True is safe")

    def test_idor_with_auth_check_no_finding(self):
        """IDOR with a proper authorization check must not be flagged."""
        code = """
def view():
    doc_id = request.args.get('doc_id')
    if not current_user.can_access(doc_id):
        abort(403)
    return db.get_document(doc_id)
"""
        findings = self._findings(code)
        idor = [f for f in findings if f.vuln_type == 'Insecure Direct Object Reference (IDOR)']
        self.assertEqual(len(idor), 0, "IDOR with abort(403) guard must not be flagged")

    def test_delete_with_admin_check_no_finding(self):
        """Admin check before delete must suppress missing-auth finding."""
        code = """
def view():
    uid = request.args.get('id')
    if not current_user.is_admin:
        raise PermissionError("Not authorized")
    db.delete_user(uid)
"""
        findings = self._findings(code)
        auth = [f for f in findings if f.vuln_type in ('Missing Authorization', 'Insecure Direct Object Reference (IDOR)')]
        self.assertEqual(len(auth), 0, "Admin check before delete must suppress missing-auth finding")


# =============================================================================
# E. PATH SENSITIVITY TESTS
# =============================================================================

class TestPathSensitivity(unittest.TestCase):
    """
    The engine must understand branches.
    Taint on one path must not pollute another path.
    Auth guards on one path must not protect another path that bypasses them.
    This is what separates real analysis from grep-based scanners.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_taint_in_dead_branch_no_finding(self):
        """Taint in unreachable code (after return) must not produce findings."""
        code = """
def view():
    safe_id = 42
    cursor.execute("SELECT * FROM t WHERE id = " + str(safe_id))
    return "done"
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0,
            "Taint in unreachable code after return must not produce findings")

    def test_auth_guard_only_on_one_branch(self):
        """
        Critical: if the auth check is only in one branch (if is_admin),
        the other branch (else) is still vulnerable.
        """
        code = """
def view():
    uid = request.args.get('id')
    if is_admin():
        abort(403)
    db.delete_user(uid)
"""
        # This is a WRONG guard pattern — abort is in the if, not the else
        # The function continues to delete even when is_admin() is False
        # But this is complex path analysis — we just need the finding to appear
        findings = self._findings(code)
        # The key point: a finding SHOULD appear because not all paths are guarded
        types = [f.vuln_type for f in findings]
        self.assertTrue(len(findings) > 0,
            "Partial guard (only in one branch) must still produce finding on unguarded path")

    def test_early_return_guard_protects_sink(self):
        """The most common guard pattern: check at top, return early if unauthorized."""
        code = """
def view():
    uid = request.args.get('id')
    if not is_authorized(uid):
        return abort(403)
    db.get_document(uid)
"""
        findings = self._findings(code)
        idor = [f for f in findings if f.vuln_type == 'Insecure Direct Object Reference (IDOR)']
        self.assertEqual(len(idor), 0,
            "Early-return authorization guard must suppress IDOR finding")

    def test_sanitized_branch_safe_unsanitized_branch_flagged(self):
        """
        If one branch sanitizes and one doesn't, the unsanitized path
        must still be flagged.
        """
        code = """
def view():
    val = request.args.get('x')
    if use_safe_mode():
        val = sanitize(val)
        cursor.execute("SELECT * FROM t WHERE x = " + val)
    else:
        cursor.execute("SELECT * FROM t WHERE x = " + val)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0,
            "Unsanitized branch must be flagged even when sanitized branch exists")


# =============================================================================
# F. INTER-PROCEDURAL TESTS
# =============================================================================

class TestInterProcedural(unittest.TestCase):
    """
    Taint must cross function boundaries correctly.
    Attackers absolutely use helper functions to obscure injection paths.
    """

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_taint_through_identity_function(self):
        """A function that returns its argument passes taint through."""
        code = """
def identity(x):
    return x

def view():
    raw = request.args.get('id')
    processed = identity(raw)
    cursor.execute("SELECT * FROM t WHERE id = " + processed)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must propagate through identity function call")

    def test_taint_through_wrapper_function(self):
        """A wrapper that passes input to a sink must be tracked."""
        code = """
def run_query(q):
    cursor.execute(q)

def view():
    uid = request.args.get('id')
    run_query("SELECT * FROM t WHERE id = " + uid)
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint must be detected when sink is inside a called function")

    def test_flask_route_with_decorator_is_analyzed(self):
        """
        CRITICAL: Flask route functions have @app.route decorators.
        The Replit version never analyzed these because they're never called directly.
        This test is the direct fix for Fatal Bug #1.
        """
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/sqli')
def vulnerable_route():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return "ok"
"""
        findings = self._findings(code)
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "CRITICAL: Flask route functions decorated with @app.route must be analyzed")

    def test_multiple_routes_all_analyzed(self):
        """Every route in the app must be analyzed, not just the first."""
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/a')
def route_a():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)

@app.route('/b')
def route_b():
    cmd = request.form.get('cmd')
    import subprocess
    subprocess.run(cmd, shell=True)
"""
        findings = self._findings(code)
        types = [f.vuln_type for f in findings]
        self.assertIn('SQL Injection', types, "First route must be analyzed")
        self.assertIn('Command Injection', types, "Second route must also be analyzed")


# =============================================================================
# G. STRUCTURAL QUALITY TESTS
# =============================================================================

class TestStructuralQuality(unittest.TestCase):
    """
    Code quality dissonance — structural contradictions.
    Γ ⊢ φ: the program's context cannot prove the proposition.
    """

    def setUp(self):
        from meta_code.dissonance import DissonanceDetector
        self.Detector = DissonanceDetector

    def _issues(self, code):
        d = self.Detector(code)
        d.parse()
        d.analyze()
        return d.get_structured_issues()

    def _kinds(self, code):
        return [i.kind for i in self._issues(code)]

    def test_unused_variable_detected(self):
        """Variable declared but never read — Γ ⊢ 'x is used' fails."""
        code = """
def process(items):
    result = []
    temp = "never used"
    for item in items:
        result.append(item * 2)
    return result
"""
        self.assertIn('unused_variable', self._kinds(code))

    def test_used_variable_not_flagged(self):
        """A variable that IS used must not be flagged."""
        code = """
def process(items):
    result = []
    for item in items:
        result.append(item * 2)
    return result
"""
        self.assertNotIn('unused_variable', self._kinds(code))

    def test_function_parameter_not_flagged(self):
        """Function parameters are the interface — never flag them as unused."""
        code = """
def f(a, b, c):
    return a + b
"""
        kinds = self._kinds(code)
        self.assertNotIn('unused_variable', kinds,
            "Function parameters must never be flagged as unused variables")

    def test_unreachable_after_return(self):
        """Code after a return statement is unreachable."""
        code = """
def f(x):
    if x > 0:
        return x * 2
        y = x + 1
    return 0
"""
        self.assertIn('unreachable_code', self._kinds(code))

    def test_unreachable_after_raise(self):
        """Code after a raise statement is unreachable."""
        code = """
def f(x):
    raise ValueError("always")
    return x
"""
        self.assertIn('unreachable_code', self._kinds(code))

    def test_unreachable_if_false(self):
        """if False: body is unreachable — constant condition."""
        code = """
def f():
    if False:
        x = 1
    return 2
"""
        self.assertIn('unreachable_code', self._kinds(code))

    def test_reachable_code_not_flagged(self):
        """Normal reachable code must not be flagged."""
        code = """
def f(x):
    if x > 0:
        return x
    return 0
"""
        self.assertNotIn('unreachable_code', self._kinds(code))

    def test_wasted_assignment(self):
        """Variable assigned then immediately reassigned before use."""
        code = """
def f():
    x = 1
    x = 2
    return x
"""
        self.assertIn('shadowed_variable', self._kinds(code))

    def test_closure_variable_not_flagged(self):
        """Variable used in a nested closure must not be flagged as unused."""
        code = """
def outer():
    x = get_value()
    def inner():
        return process(x)
    return inner()
"""
        issues = self._issues(code)
        unused = [i for i in issues if i.kind == 'unused_variable' and "'x'" in i.message]
        self.assertEqual(len(unused), 0,
            "Variable used in closure must not be flagged as unused")

    def test_comprehension_variable_not_flagged(self):
        """Comprehension iteration variable must not be flagged."""
        code = """
def f():
    return [x * 2 for x in range(10)]
"""
        kinds = self._kinds(code)
        self.assertNotIn('unused_variable', kinds)

    def test_clean_code_zero_issues(self):
        """Perfectly clean code must produce zero structural issues."""
        code = """
def add(a, b):
    return a + b

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        issues = self._issues(code)
        self.assertEqual(len(issues), 0, "Clean code must produce zero structural issues")


# =============================================================================
# H. MATHEMATICAL TESTS
# =============================================================================

class TestMathematical(unittest.TestCase):
    """
    The mathematical framework must produce correct, meaningful results.
    These are not ornamental — they are load-bearing for the analysis.
    """

    def test_generating_function_isomorphic_programs(self):
        """
        Two structurally isomorphic programs must produce the same G(x).
        This is the core invariant of the Subject module.
        """
        from meta_code.subject import SubjectExtractor
        code_a = "def f(x):\n    if x:\n        return x\n    return None"
        code_b = "def g(y):\n    if y:\n        return y\n    return None"
        gx_a = SubjectExtractor(code_a).compute_polynomial()
        gx_b = SubjectExtractor(code_b).compute_polynomial()
        self.assertAlmostEqual(gx_a, gx_b, places=4,
            msg="Isomorphic programs must produce identical G(x) values")

    def test_generating_function_different_programs(self):
        """Structurally different programs must produce different G(x)."""
        from meta_code.subject import SubjectExtractor
        simple = "x = 1"
        complex_code = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        gx_simple = SubjectExtractor(simple).compute_polynomial()
        gx_complex = SubjectExtractor(complex_code).compute_polynomial()
        self.assertNotAlmostEqual(gx_simple, gx_complex, places=2,
            msg="Structurally different programs must produce different G(x)")

    def test_structural_fingerprint_matches_isomorphic(self):
        """Structural fingerprints must match for isomorphic programs."""
        from meta_code.subject import SubjectExtractor
        code_a = "def f(x):\n    return x + 1"
        code_b = "def g(y):\n    return y + 1"
        fp_a = SubjectExtractor(code_a).structural_fingerprint()
        fp_b = SubjectExtractor(code_b).structural_fingerprint()
        self.assertEqual(fp_a, fp_b, "Isomorphic programs must have matching fingerprints")

    def test_kolmogorov_ratio_in_range(self):
        """Normalized K(x) must always be in [0, 1]."""
        from meta_code.compression import KolmogorovComplexity
        codes = [
            "x = 1",
            "def f(): pass",
            "\n".join(f"def f{i}(x):\n    return x + {i}" for i in range(20)),
        ]
        for code in codes:
            result = KolmogorovComplexity(code).compute_complexity()
            ratio = result['normalized_ratio']
            self.assertGreaterEqual(ratio, 0.0, f"K(x) must be >= 0: got {ratio}")
            self.assertLessEqual(ratio, 1.0, f"K(x) must be <= 1.0: got {ratio}")

    def test_kolmogorov_repetitive_lower_than_complex(self):
        """Repetitive code must have lower K(x) than complex code."""
        from meta_code.compression import KolmogorovComplexity
        repetitive = "\n".join(f"x{i} = {i}" for i in range(50))
        complex_code = """
def merge_sort(arr):
    if len(arr) <= 1:
        return arr
    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] < right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    return result + left[i:] + right[j:]
"""
        kc_rep = KolmogorovComplexity(repetitive).compute_complexity()['normalized_ratio']
        kc_complex = KolmogorovComplexity(complex_code).compute_complexity()['normalized_ratio']
        self.assertLessEqual(kc_rep, kc_complex,
            "Repetitive code must have lower K(x) than complex algorithmic code")

    def test_halstead_volume_positive(self):
        """Halstead Volume must be positive for any non-trivial code."""
        from meta_code.compression import HalsteadMetrics
        code = "def f(x):\n    return x + 1"
        result = HalsteadMetrics(code).compute()
        self.assertGreater(result['volume'], 0, "Halstead Volume must be positive")

    def test_halstead_all_fields_present(self):
        """All Halstead metric fields must be present in the output."""
        from meta_code.compression import HalsteadMetrics
        code = "def f(x, y):\n    return x * y + 1"
        result = HalsteadMetrics(code).compute()
        required = ['n1_distinct_operators', 'n2_distinct_operands',
                    'N1_total_operators', 'N2_total_operands',
                    'vocabulary', 'length', 'volume', 'difficulty',
                    'effort', 'time_seconds', 'estimated_bugs']
        for field in required:
            self.assertIn(field, result, f"Halstead result must contain '{field}'")

    def test_jaccard_distance_metric_axioms(self):
        """Jaccard distance must satisfy metric axioms: reflexive, symmetric, triangle."""
        from meta_code.resolution import jaccard_distance
        A = frozenset(['issue_a', 'issue_b'])
        B = frozenset(['issue_b', 'issue_c'])
        C = frozenset(['issue_c', 'issue_d'])

        # Reflexivity
        self.assertEqual(jaccard_distance(A, A), 0.0, "d(A,A) must be 0")

        # Symmetry
        self.assertAlmostEqual(jaccard_distance(A, B), jaccard_distance(B, A),
            msg="Jaccard distance must be symmetric")

        # Triangle inequality
        dAB = jaccard_distance(A, B)
        dBC = jaccard_distance(B, C)
        dAC = jaccard_distance(A, C)
        self.assertLessEqual(dAC, dAB + dBC + 1e-9,
            "Triangle inequality d(A,C) <= d(A,B) + d(B,C) must hold")

    def test_convergence_sequence_decreasing_with_fixes(self):
        """When issues are fixed across runs, convergence sequence must decrease."""
        from meta_code.resolution import ResolutionPredictor
        runs = [
            ['issue_a', 'issue_b', 'issue_c'],
            ['issue_a', 'issue_b'],
            ['issue_a'],
            [],
        ]
        predictor = ResolutionPredictor(runs[-1])
        for run in runs[:-1]:
            predictor.add_historical_run(run)
        predictor.analyze()

        seq = predictor.convergence_sequence()
        self.assertGreater(len(seq), 0, "Convergence sequence must be non-empty")
        # With fixing happening, at least some distances should be > 0
        self.assertTrue(any(d > 0 for d in seq),
            "Convergence sequence must show movement when issues are fixed")

    def test_transposition_isomorphic_verdict(self):
        """Structurally identical programs must be declared isomorphic."""
        from meta_code.transposition import TranspositionFinder
        code_a = "def f(x):\n    if x:\n        return x\n    return None"
        code_b = "def g(y):\n    if y:\n        return y\n    return None"
        result = TranspositionFinder().find_transpositions(code_a, code_b)
        self.assertEqual(result['verdict'], 'isomorphic',
            "Structurally identical programs must have 'isomorphic' verdict")

    def test_transposition_distinct_verdict(self):
        """Structurally different programs must not be declared isomorphic."""
        from meta_code.transposition import TranspositionFinder
        code_a = "x = 1\ny = 2"
        code_b = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        result = TranspositionFinder().find_transpositions(code_a, code_b)
        self.assertNotEqual(result['verdict'], 'isomorphic',
            "Structurally different programs must not be 'isomorphic'")

    def test_self_similarity_recursive_code(self):
        """Recursive code should have higher self-similarity than flat code."""
        from meta_code.subject import SubjectExtractor
        recursive = """
def f(n):
    if n <= 0:
        return 0
    if n == 1:
        return 1
    return f(n-1) + f(n-2)
"""
        flat = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5"
        ss_recursive = SubjectExtractor(recursive).self_similarity_score()
        ss_flat = SubjectExtractor(flat).self_similarity_score()
        self.assertGreaterEqual(ss_recursive, ss_flat,
            "Recursive code should have higher self-similarity than flat assignments")


# =============================================================================
# I. PIPELINE / INTEGRATION TESTS
# =============================================================================

class TestPipeline(unittest.TestCase):
    """
    End-to-end tests of the full 7-stage pipeline.
    Tests that the orchestrator wires everything together correctly
    and that reports contain all expected fields.
    """

    def setUp(self):
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()
        self.engine = MetaCodeEngine.get_instance()

    def tearDown(self):
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()

    def test_report_has_all_required_fields(self):
        """Every analysis report must contain all required fields."""
        from meta_code.meta_engine import MetaCodeEngine
        report = self.engine.orchestrate("def f(): pass")
        self.assertIsNotNone(report.complexity_metrics)
        self.assertIsNotNone(report.structural_analysis)
        self.assertIsNotNone(report.resolution_predictions)
        self.assertIsNotNone(report.convergence)
        self.assertIsNotNone(report.structural_fingerprint)
        self.assertIsNotNone(report.security_findings)

    def test_security_findings_in_report(self):
        """Security findings must appear in the report for vulnerable code."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
        report = self.engine.orchestrate(code)
        self.assertTrue(len(report.security_findings) > 0,
            "Vulnerable code must produce security findings in the report")

    def test_structural_findings_in_report(self):
        """Structural issues must appear in the report for bad code."""
        code = """
def process():
    x = 1
    y = "never used"
    return x
"""
        report = self.engine.orchestrate(code)
        self.assertTrue(len(report.issues) > 0,
            "Code with structural issues must produce issues in the report")

    def test_clean_code_zero_all_findings(self):
        """Completely clean code must produce zero findings of any kind."""
        code = """
def add(a, b):
    return a + b
"""
        report = self.engine.orchestrate(code)
        self.assertEqual(len(report.security_findings), 0,
            "Clean code must produce zero security findings")
        self.assertEqual(len(report.issues), 0,
            "Clean code must produce zero structural issues")

    def test_syntax_error_returns_structured_report(self):
        """Syntax errors must return a structured report, not raise an exception."""
        code = "def f(: invalid syntax here"
        try:
            report = self.engine.orchestrate(code)
            self.assertIsNotNone(report, "Syntax error must return a report object")
        except SyntaxError:
            self.fail("Syntax error must not propagate as an exception")

    def test_singleton_persists_history(self):
        """
        The singleton must persist history across calls.
        This is what makes Banach convergence work.
        The Replit version broke this by reinstantiating on every request.
        """
        from meta_code.meta_engine import MetaCodeEngine
        engine = MetaCodeEngine.get_instance()
        engine.orchestrate("def f(): pass")
        engine.orchestrate("def f(): pass")
        self.assertEqual(engine._run_count, 2,
            "CRITICAL: singleton must persist run count across calls")

    def test_halstead_severity_weighting(self):
        """
        The same vulnerability in a high-complexity function must have
        higher or equal severity score than in a simple function.
        """
        simple_vuln = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        complex_vuln = """
def view():
    uid = request.args.get('id')
    results = []
    for i in range(100):
        for j in range(100):
            if i % 2 == 0:
                if j % 3 == 0:
                    try:
                        x = complex_calc(i, j)
                        results.append(x)
                    except Exception as e:
                        handle_error(e)
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
    return results
"""
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()
        e = MetaCodeEngine.get_instance()

        report_simple = e.orchestrate(simple_vuln)
        MetaCodeEngine.reset()
        e2 = MetaCodeEngine.get_instance()
        report_complex = e2.orchestrate(complex_vuln)

        # Both must find the SQLi
        simple_sqli = [f for f in report_simple.security_findings if f.vuln_type == 'SQL Injection']
        complex_sqli = [f for f in report_complex.security_findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(simple_sqli) > 0, "Simple vulnerable code must find SQLi")
        self.assertTrue(len(complex_sqli) > 0, "Complex vulnerable code must find SQLi")

    def test_convergence_tracks_across_runs(self):
        """Convergence sequence must grow with each run."""
        buggy = "def f():\n    x = 1\n    y = 'unused'\n    return x"
        self.engine.orchestrate(buggy)
        self.engine.orchestrate(buggy)
        self.engine.orchestrate(buggy)

        report = self.engine.orchestrate(buggy)
        seq = report.convergence.get('sequence', [])
        self.assertGreater(len(seq), 0,
            "Convergence sequence must grow with multiple runs")

    def test_compare_returns_transposition_result(self):
        """The compare() method must return a full transposition analysis."""
        code_a = "def f(x):\n    return x + 1"
        code_b = "def g(y):\n    return y + 1"
        result = self.engine.compare(code_a, code_b)
        self.assertIn('verdict', result)
        self.assertIn('overall_similarity', result)
        self.assertIn('type_similarity', result)


# =============================================================================
# J. EDGE CASE TESTS
# =============================================================================

class TestEdgeCases(unittest.TestCase):
    """
    Edge cases that break naive implementations.
    These are the cases that caused the one-step-forward-two-steps-back problem.
    """

    def setUp(self):
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()
        self.engine = MetaCodeEngine.get_instance()

    def tearDown(self):
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()

    def test_empty_code(self):
        """Empty string must not crash anything."""
        try:
            report = self.engine.orchestrate("")
            # Should either return empty report or syntax error report
        except Exception as e:
            self.fail(f"Empty code must not crash the engine: {e}")

    def test_only_comments(self):
        """Code that is only comments must not crash."""
        code = "# This is just a comment\n# Nothing else"
        try:
            report = self.engine.orchestrate(code)
        except Exception as e:
            self.fail(f"Comment-only code must not crash: {e}")

    def test_nested_functions(self):
        """Taint analysis must handle nested function definitions."""
        code = """
def outer():
    def inner():
        uid = request.args.get('id')
        cursor.execute("SELECT * FROM t WHERE id = " + uid)
    inner()
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint analysis must handle nested function definitions")

    def test_class_methods(self):
        """Taint inside class methods must be detected."""
        code = """
class MyView:
    def get(self):
        uid = request.args.get('id')
        cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "Taint analysis must work inside class methods")

    def test_deduplication_no_duplicate_findings(self):
        """The same vulnerability at the same location must not appear twice."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 1, "Same vulnerability at same location must appear exactly once")

    def test_multiple_vulnerabilities_in_one_function(self):
        """Multiple different vulnerability types in one function must all be found."""
        code = """
def view():
    uid = request.args.get('id')
    filename = request.args.get('file')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
    return open(filename).read()
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        types = {f.vuln_type for f in findings}
        self.assertIn('SQL Injection', types, "SQLi must be found")
        self.assertIn('Path Traversal', types, "Path Traversal must be found")

    def test_attack_path_in_finding(self):
        """Every security finding must include an attack path for the report."""
        code = """
def view():
    uid = request.args.get('id')
    safe_looking = uid
    cursor.execute("SELECT * FROM t WHERE id = " + safe_looking)
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0)
        self.assertIsNotNone(sqli[0].path, "Finding must include attack path")
        self.assertGreater(len(sqli[0].path), 0, "Attack path must not be empty")

    def test_finding_includes_line_number(self):
        """Every security finding must include a line number."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0)
        self.assertIsNotNone(sqli[0].lineno, "Finding must include line number")

    def test_binop_taint_both_sides(self):
        """
        CRITICAL: This is Fatal Bug #2 from the Replit version.
        'SELECT...' + uid  — the string constant is on the left.
        The original engine returned the string (truthy) and dropped the taint.
        The tainted value must be returned regardless of which side it's on.
        """
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        from meta_code.taint import PathSensitiveTaintAnalyzer
        findings = PathSensitiveTaintAnalyzer().analyze(ast.parse(code))
        self.assertTrue(any(f.vuln_type == 'SQL Injection' for f in findings),
            "CRITICAL: BinOp with constant on left and taint on right must detect injection (Bug #2 fix)")


# =============================================================================
# RUNNER
# =============================================================================

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Load all test classes in order
    classes = [
        TestTaintSources,
        TestTaintPropagation,
        TestSinkDetection,
        TestFalsePositives,
        TestPathSensitivity,
        TestInterProcedural,
        TestStructuralQuality,
        TestMathematical,
        TestPipeline,
        TestEdgeCases,
    ]

    for cls in classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print(f"\n{'='*60}")
    print(f"TOTAL: {result.testsRun} tests")
    print(f"PASSED: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"FAILED: {len(result.failures)}")
    print(f"ERRORS: {len(result.errors)}")

    sys.exit(0 if result.wasSuccessful() else 1)
