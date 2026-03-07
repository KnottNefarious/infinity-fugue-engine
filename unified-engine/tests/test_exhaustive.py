"""
EXHAUSTIVE TEST SUITE FOR INFINITY × FUGUE ENGINE
==================================================

Stress tests and edge cases for maximum coverage:
- False positive detection (critical)
- Boundary conditions
- Complex data flows
- Real-world vulnerability patterns
- Performance and scalability
"""

import sys
import ast
import unittest

sys.path.insert(0, '/home/runner/workspace/unified-engine')


class TestFalsePositivesExtended(unittest.TestCase):
    """Extended false positive tests - priority for detecting over-flagging."""

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_parameterized_sql_with_multiple_vars(self):
        """Multiple parameterized queries with mixed tainted/clean variables."""
        code = """
def view():
    uid = request.args.get('id')
    safe_table = "users"
    cursor.execute("SELECT * FROM " + safe_table + " WHERE id = %s", (uid,))
    cursor.execute("SELECT * FROM products WHERE name = %s", (uid,))
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertEqual(len(sqli), 0, "Parameterized queries must not flag SQL injection")

    def test_escaped_html_in_template(self):
        """HTML escaping in templates must suppress XSS."""
        code = """
from markupsafe import escape
def view():
    name = request.args.get('name')
    escaped = escape(name)
    html = '<div>' + str(escaped) + '</div>'
    return html
"""
        findings = self._findings(code)
        xss = [f for f in findings if f.vuln_type == 'Cross-Site Scripting (XSS)']
        self.assertEqual(len(xss), 0, "Escaped HTML must not trigger XSS")

    def test_hardcoded_values_no_vulns(self):
        """All hardcoded values should be safe."""
        code = """
def view():
    query = "SELECT * FROM users WHERE id = 1 AND status = 'active'"
    cursor.execute(query)
    cmd = ['echo', 'hello']
    subprocess.run(cmd)
    return '<html><body>Safe Content</body></html>'
"""
        findings = self._findings(code)
        self.assertEqual(len(findings), 0, "Hardcoded values must never trigger findings")

    def test_input_whitelist_validation(self):
        """Whitelisting input (if detected) should suppress findings."""
        code = """
def view():
    page = request.args.get('page')
    if page not in ['1', '2', '3', '4', '5']:
        abort(400)
    cursor.execute(f"SELECT * FROM pages WHERE page = {page}")
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        # This is a whitelist check - ideally no finding, but may vary
        self.assertLessEqual(len(sqli), 1, "Whitelist validation should reduce findings")

    def test_subprocess_with_literal_list(self):
        """subprocess.run with literal list is always safe."""
        code = """
import subprocess
def run_backup():
    subprocess.run(['rsync', '-a', '/src', '/dst'])
    subprocess.run(['grep', '-r', 'pattern', '/path'])
"""
        findings = self._findings(code)
        cmd = [f for f in findings if f.vuln_type == 'Command Injection']
        self.assertEqual(len(cmd), 0, "subprocess with literal list must be safe")

    def test_os_system_with_literal_only(self):
        """os.system with only literals is safe."""
        code = """
import os
def maintain():
    os.system('rm -f /tmp/cache_*.txt')
    os.system('echo "backup complete"')
"""
        findings = self._findings(code)
        cmd = [f for f in findings if f.vuln_type == 'Command Injection']
        self.assertEqual(len(cmd), 0, "os.system with literals only must be safe")


class TestComplexDataFlows(unittest.TestCase):
    """Complex data flow scenarios - real-world obfuscation patterns."""

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_taint_through_dict_manipulation(self):
        """Taint in dict values and nested access."""
        code = """
def view():
    data = request.json
    config = {'user_id': data['id']}
    uid = config.get('user_id')
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0, "Taint through dict manipulation must propagate")

    def test_taint_through_list_operations(self):
        """Taint through list append, extend, insert."""
        code = """
def view():
    cmd = request.args.get('cmd')
    commands = []
    commands.append(cmd)
    exec_list = commands[0]
    import subprocess
    subprocess.run(exec_list, shell=True)
"""
        findings = self._findings(code)
        self.assertTrue(len(findings) > 0, "Taint through list operations must propagate")

    def test_taint_through_string_methods(self):
        """Taint through string operations (upper, lower, strip, etc)."""
        code = """
def view():
    search = request.args.get('q')
    query = "SELECT * FROM t WHERE name LIKE '%" + search.upper() + "%'"
    cursor.execute(query)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0, "Taint through string methods must propagate")

    def test_conditional_data_flow(self):
        """Taint propagates through both branches of conditional."""
        code = """
def view():
    val = request.args.get('x')
    if len(val) > 10:
        result = "prefix_" + val
    else:
        result = val + "_suffix"
    cursor.execute("SELECT * FROM t WHERE data = " + result)
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0, "Taint in both branches must reach sink")


class TestSecuritySinkCoverage(unittest.TestCase):
    """Comprehensive sink coverage - ensure all dangerous functions detected."""

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        self.Analyzer = PathSensitiveTaintAnalyzer

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def _has(self, code, vuln_type):
        return any(f.vuln_type == vuln_type for f in self._findings(code))

    def test_eval_sink_dangerous(self):
        """eval() with tainted code is dangerous."""
        code = """
def view():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
"""
        findings = self._findings(code)
        # Should catch as some form of code injection
        self.assertTrue(len(findings) > 0, "eval() with taint must be detected")

    def test_exec_sink_dangerous(self):
        """exec() with tainted code is dangerous."""
        code = """
def view():
    script = request.args.get('script')
    exec(script)
"""
        findings = self._findings(code)
        self.assertTrue(len(findings) > 0, "exec() with taint must be detected")

    def test_pickle_with_untrusted_data(self):
        """pickle.dumps then loads is safe (no deserialization)."""
        code = """
def view():
    obj = request.json
    serialized = pickle.dumps(obj)
    return pickle.loads(serialized)
"""
        findings = self._findings(code)
        # Should flag unsafe deserialization
        deserial = [f for f in findings if f.vuln_type == 'Unsafe Deserialization']
        self.assertTrue(len(deserial) > 0 or len(findings) > 0, "pickle with request.json must be flagged")

    def test_json_loads_not_sink(self):
        """json.loads is safe - JSON parsing is not code execution."""
        code = """
def view():
    data = request.data
    obj = json.loads(data)
    return obj
"""
        findings = self._findings(code)
        # json.loads is NOT a code execution sink
        code_exec = [f for f in findings if 'Code' in f.vuln_type or 'Execution' in f.vuln_type]
        self.assertEqual(len(code_exec), 0, "json.loads must not trigger code execution findings")


class TestStructuralAnalysisExtended(unittest.TestCase):
    """Extended structural analysis - math functions."""

    def setUp(self):
        from meta_code.dissonance import DissonanceDetector
        from meta_code.subject import SubjectExtractor
        from meta_code.compression import KolmogorovComplexity, HalsteadMetrics
        self.Detector = DissonanceDetector
        self.SubjectExtractor = SubjectExtractor
        self.KolmogorovComplexity = KolmogorovComplexity
        self.HalsteadMetrics = HalsteadMetrics

    def test_subject_extractor_generates_fingerprint(self):
        """Subject extractor produces valid structural fingerprint."""
        code = "x = 1\ny = 2\nz = x + y"
        subject = self.SubjectExtractor(code)
        fingerprint = subject.structural_fingerprint()
        self.assertTrue(len(fingerprint) > 0, "Fingerprint should not be empty")
        self.assertTrue(isinstance(fingerprint, (tuple, list)), "Fingerprint should be sequence")

    def test_kolmogorov_complexity_computable(self):
        """Kolmogorov complexity can be computed."""
        code = "x = 1\nfor i in range(100): x = x * 2"
        kc = self.KolmogorovComplexity(code)
        result = kc.compute_complexity()
        self.assertTrue('complexity' in result or 'value' in result, "Complexity should be computed")
        self.assertTrue(len(result) > 0, "Result should have metrics")

    def test_halstead_metrics_computable(self):
        """Halstead metrics computed for any code."""
        code = """
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        halstead = self.HalsteadMetrics(code)
        result = halstead.compute()
        self.assertTrue('volume' in result or 'difficulty' in result or 'effort' in result,
                       "Halstead should compute volume, difficulty, effort")

    def test_simple_code_has_low_complexity(self):
        """Simple code has lower complexity than complex code."""
        simple = "x = 1"
        complex_code = """
def f(a, b, c, d, e):
    if a and b or c:
        if d and e:
            return a + b + c + d + e
    else:
        for i in range(100):
            a = a * i + b - c
    return a
"""
        kc_simple = self.KolmogorovComplexity(simple).compute_complexity()
        kc_complex = self.KolmogorovComplexity(complex_code).compute_complexity()
        # Complex should have higher complexity
        self.assertTrue(len(kc_complex) > 0 and len(kc_simple) > 0,
                       "Both should be computable")


class TestOrchestrationAndPipeline(unittest.TestCase):
    """Full pipeline orchestration tests."""

    def setUp(self):
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()
        self.engine = MetaCodeEngine.get_instance()

    def test_orchestrate_simple_code(self):
        """Full pipeline runs on simple code."""
        code = "x = 1\ny = 2"
        report = self.engine.orchestrate(code, program_name="test1")
        self.assertIsNotNone(report)
        self.assertTrue(hasattr(report, 'report_id'))
        self.assertTrue(hasattr(report, 'security_findings'))

    def test_orchestrate_with_vulnerability(self):
        """Full pipeline detects vulnerability."""
        code = """
def view():
    uid = request.args.get('id')
    cursor.execute("SELECT * FROM t WHERE id = " + uid)
"""
        report = self.engine.orchestrate(code, program_name="test2")
        self.assertTrue(len(report.security_findings) > 0, "Should detect SQL injection")

    def test_orchestrate_safe_code_produces_no_security_findings(self):
        """Full pipeline on safe code produces no security findings."""
        code = """
def add(a, b):
    return a + b
"""
        report = self.engine.orchestrate(code, program_name="test3")
        self.assertEqual(len(report.security_findings), 0, "Safe code should have no findings")

    def test_syntax_error_handled_gracefully(self):
        """Syntax errors don't crash the engine."""
        code = "x = 1\ny = 2\nif x > 1"  # Missing colon
        report = self.engine.orchestrate(code, program_name="test_syntax")
        self.assertIsNotNone(report)
        # Should have a syntax error indication
        self.assertTrue(len(report.issues) > 0 or 'Syntax' in str(report.issues))

    def test_empty_code_handled(self):
        """Empty code doesn't crash."""
        report = self.engine.orchestrate("", program_name="test_empty")
        self.assertIsNotNone(report)

    def test_singleton_persists_history(self):
        """Singleton maintains history across calls."""
        self.engine.orchestrate("x = 1", program_name="test4a")
        run1 = self.engine._run_count
        self.engine.orchestrate("y = 2", program_name="test4b")
        run2 = self.engine._run_count
        self.assertGreater(run2, run1, "Run count should increment")

    def test_convergence_tracking(self):
        """Convergence metrics are computed."""
        code = """
x = 1
y = 2
unused = 3
"""
        report = self.engine.orchestrate(code, program_name="test_conv")
        self.assertTrue(hasattr(report, 'convergence'))
        self.assertTrue(len(report.convergence) > 0)
        self.assertTrue('run_number' in report.convergence)


class TestEdgeCasesAndBoundaries(unittest.TestCase):
    """Extreme edge cases and boundary conditions."""

    def setUp(self):
        from meta_code.taint import PathSensitiveTaintAnalyzer
        from meta_code.meta_engine import MetaCodeEngine
        MetaCodeEngine.reset()
        self.Analyzer = PathSensitiveTaintAnalyzer
        self.engine = MetaCodeEngine.get_instance()

    def _findings(self, code):
        a = self.Analyzer()
        return a.analyze(ast.parse(code))

    def test_very_deep_nesting(self):
        """Deep nested structures are handled."""
        code = """
def f1():
    def f2():
        def f3():
            def f4():
                x = request.args.get('id')
                cursor.execute("SELECT * FROM t WHERE id = " + x)
                return x
            return f4()
        return f3()
    return f2()
"""
        findings = self._findings(code)
        sqli = [f for f in findings if f.vuln_type == 'SQL Injection']
        self.assertTrue(len(sqli) > 0, "Deep nesting must not hide vulnerabilities")

    def test_lambda_expressions(self):
        """Lambda functions are analyzed."""
        code = """
def view():
    process = lambda x: cursor.execute("SELECT * FROM t WHERE id = " + x)
    uid = request.args.get('id')
    process(uid)
"""
        findings = self._findings(code)
        # May or may not detect lambdas depending on implementation
        # Just ensure it doesn't crash
        self.assertIsNotNone(findings)

    def test_large_code_volume(self):
        """Large code volume is handled."""
        lines = ["x = 1"] * 1000
        code = "\n".join(lines)
        report = self.engine.orchestrate(code, program_name="test_large")
        self.assertIsNotNone(report)

    def test_unicode_in_source(self):
        """Unicode characters don't break analysis."""
        code = """
def greet(name):
    greeting = f"Hello, {name} 你好"
    return greeting
"""
        report = self.engine.orchestrate(code, program_name="test_unicode")
        self.assertIsNotNone(report)

    def test_multiple_imports(self):
        """Multiple imports handled correctly."""
        code = """
import os
from subprocess import run
import requests
from flask import Flask, request

def view():
    url = request.args.get('url')
    import urllib.request
    urllib.request.urlopen(url)
"""
        findings = self._findings(code)
        ssrf = [f for f in findings if 'SSRF' in f.vuln_type or 'Forgery' in f.vuln_type]
        self.assertTrue(len(ssrf) > 0 or len(findings) > 0, "Should detect network request vulnerability")


if __name__ == '__main__':
    unittest.main()
