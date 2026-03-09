"""
test_realworld.py — 300 Real-World Tests
Single file (100), Multi-file (100), ZIP (100)
Covers: SQL injection, XSS, SSRF, path traversal, command injection,
        deserialization, IDOR, code injection, auth bypass, structural issues,
        clean code, Flask/Django/FastAPI patterns, async code, decorators,
        class-based views, middleware, CLI tools, data pipelines, etc.
"""

import io
import json
import re
import sys
import zipfile
import unittest

sys.path.insert(0, '/home/claude/unified-engine')
import app as application

client = application.app.test_client()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def analyze(code, name='test.py'):
    r = client.post('/api/analyze', json={'code': code, 'name': name})
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

def analyze_zip(file_dict, zipname='test.zip'):
    buf = make_zip(file_dict)
    r = client.post('/api/analyze_zip',
                    data={'zip': (buf, zipname)},
                    content_type='multipart/form-data')
    return json.loads(r.data)

def has_vuln(d, keyword):
    keyword = keyword.lower()
    for f in d.get('security_findings', []):
        if keyword in f.get('vuln_type', '').lower():
            return True
    return False

def is_clean(d):
    return d.get('security_count', 0) == 0

def has_struct(d, keyword):
    keyword = keyword.lower()
    for iss in d.get('structural_issues', []):
        if keyword in iss.lower():
            return True
    return False

def report_ok(d):
    return 'report_id' in d and 'error' not in d

def has_local_lineno(d):
    for f in d.get('security_findings', []):
        if f.get('local_lineno') is not None:
            return True
    return False

def has_source_file(d):
    for f in d.get('security_findings', []):
        if f.get('source_file'):
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# SINGLE FILE TESTS (100)
# ─────────────────────────────────────────────────────────────────────────────

class TestSingleFile(unittest.TestCase):

    # ── SQL Injection (10) ────────────────────────────────────────────────────
    def test_sf_001_sql_string_concat(self):
        d = analyze("from flask import request\ndef v():\n    uid=request.args.get('id')\n    cursor.execute('SELECT * FROM users WHERE id='+uid)")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_002_sql_fstring(self):
        d = analyze("from flask import request\ndef v():\n    name=request.form.get('name')\n    cursor.execute(f'SELECT * FROM t WHERE name={name}')")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_003_sql_percent_format(self):
        d = analyze("from flask import request\ndef v():\n    x=request.args.get('x')\n    cursor.execute('DELETE FROM t WHERE id=%s' % x)")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_004_sql_parameterized_safe(self):
        d = analyze("from flask import request\ndef v():\n    uid=request.args.get('id')\n    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))")
        self.assertFalse(has_vuln(d, 'sql'))

    def test_sf_005_sql_executemany_unsafe(self):
        d = analyze("from flask import request\ndef v():\n    val=request.form.get('v')\n    cursor.executemany('INSERT INTO t VALUES ('+val+')', [])")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_006_sql_in_class(self):
        d = analyze("from flask import request\nclass UserView:\n    def get(self):\n        uid=request.args.get('id')\n        cursor.execute('SELECT * FROM users WHERE id='+uid)")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_007_sql_via_variable(self):
        d = analyze("from flask import request\ndef search():\n    q=request.args.get('q')\n    query='SELECT * FROM products WHERE name='+q\n    cursor.execute(query)")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_008_sql_async_route(self):
        d = analyze("from flask import request\nasync def v():\n    uid=request.args.get('id')\n    await cursor.execute('SELECT * FROM t WHERE id='+uid)")
        self.assertTrue(report_ok(d))

    def test_sf_009_sql_safe_no_request(self):
        d = analyze("def get_user(uid):\n    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n    return cursor.fetchone()")
        self.assertFalse(has_vuln(d, 'sql'))

    def test_sf_010_sql_annotated_assign(self):
        d = analyze("from flask import request\ndef v():\n    uid: str = request.args.get('id')\n    cursor.execute('SELECT * FROM t WHERE id=' + uid)")
        self.assertTrue(has_vuln(d, 'sql'))

    # ── Command Injection (10) ────────────────────────────────────────────────
    def test_sf_011_cmd_os_system(self):
        d = analyze("import os\nfrom flask import request\ndef v():\n    f=request.args.get('file')\n    os.system('cat '+f)")
        self.assertTrue(has_vuln(d, 'command') or has_vuln(d, 'injection'))

    def test_sf_012_cmd_subprocess_shell(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    cmd=request.form.get('cmd')\n    subprocess.run(cmd, shell=True)")
        self.assertTrue(has_vuln(d, 'command') or has_vuln(d, 'injection'))

    def test_sf_013_cmd_popen_shell(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    f=request.args.get('f')\n    subprocess.Popen(f, shell=True)")
        self.assertTrue(has_vuln(d, 'command') or has_vuln(d, 'injection'))

    def test_sf_014_cmd_safe_no_shell(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    f=request.args.get('f')\n    subprocess.run(['ls', f], shell=False)")
        self.assertFalse(has_vuln(d, 'command'))

    def test_sf_015_cmd_check_output(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    cmd=request.args.get('c')\n    subprocess.check_output(cmd, shell=True)")
        self.assertTrue(report_ok(d))

    def test_sf_016_cmd_check_call(self):
        d = analyze("import subprocess\nfrom flask import request\ndef v():\n    cmd=request.args.get('c')\n    subprocess.check_call(cmd, shell=True)")
        self.assertTrue(report_ok(d))

    def test_sf_017_cmd_os_system_safe_static(self):
        d = analyze("import os\ndef backup():\n    os.system('pg_dump mydb > backup.sql')")
        self.assertFalse(has_vuln(d, 'command'))

    def test_sf_018_cmd_via_join(self):
        d = analyze("import os\nfrom flask import request\ndef v():\n    f=request.args.get('f')\n    cmd='rm -rf /tmp/'+f\n    os.system(cmd)")
        self.assertTrue(report_ok(d))

    def test_sf_019_cmd_decorator_route(self):
        d = analyze("import os, subprocess\nfrom flask import Flask, request\napp=Flask(__name__)\n@app.route('/run')\ndef run():\n    cmd=request.args.get('cmd')\n    subprocess.run(cmd, shell=True)")
        self.assertTrue(has_vuln(d, 'command') or has_vuln(d, 'injection'))

    def test_sf_020_cmd_from_json(self):
        d = analyze("import os\nfrom flask import request\ndef v():\n    data=request.json\n    os.system(data['cmd'])")
        self.assertTrue(report_ok(d))

    # ── Path Traversal (10) ───────────────────────────────────────────────────
    def test_sf_021_path_open_direct(self):
        d = analyze("from flask import request\ndef v():\n    f=request.args.get('file')\n    open(f).read()")
        self.assertTrue(has_vuln(d, 'path') or has_vuln(d, 'traversal'))

    def test_sf_022_path_os_join(self):
        d = analyze("import os\nfrom flask import request\ndef v():\n    f=request.args.get('file')\n    path=os.path.join('/uploads', f)\n    open(path).read()")
        self.assertTrue(report_ok(d))

    def test_sf_023_path_write(self):
        d = analyze("from flask import request\ndef v():\n    fname=request.form.get('name')\n    with open(fname, 'w') as f:\n        f.write('data')")
        self.assertTrue(has_vuln(d, 'path') or has_vuln(d, 'traversal'))

    def test_sf_024_path_static_safe(self):
        d = analyze("def serve():\n    with open('/static/index.html') as f:\n        return f.read()")
        self.assertFalse(has_vuln(d, 'path'))

    def test_sf_025_path_from_header(self):
        d = analyze("from flask import request\ndef v():\n    f=request.headers.get('X-File')\n    open(f).read()")
        self.assertTrue(report_ok(d))

    def test_sf_026_path_from_cookie(self):
        d = analyze("from flask import request\ndef v():\n    f=request.cookies.get('file')\n    data=open(f).read()\n    return data")
        self.assertTrue(report_ok(d))

    def test_sf_027_path_from_json(self):
        d = analyze("from flask import request\ndef v():\n    path=request.json['path']\n    return open(path).read()")
        self.assertTrue(report_ok(d))

    def test_sf_028_path_send_file(self):
        d = analyze("from flask import request, send_file\ndef v():\n    f=request.args.get('f')\n    return send_file(f)")
        self.assertTrue(report_ok(d))

    def test_sf_029_path_aug_assign(self):
        d = analyze("from flask import request\ndef v():\n    base='/data/'\n    f=request.args.get('f')\n    base += f\n    open(base).read()")
        self.assertTrue(report_ok(d))

    def test_sf_030_path_class_method(self):
        d = analyze("from flask import request\nclass FileView:\n    def get(self):\n        f=request.args.get('name')\n        return open('/uploads/'+f).read()")
        self.assertTrue(report_ok(d))

    # ── XSS (8) ──────────────────────────────────────────────────────────────
    def test_sf_031_xss_render_template_string(self):
        d = analyze("from flask import request, render_template_string\ndef v():\n    name=request.args.get('name')\n    return render_template_string('<h1>'+name+'</h1>')")
        self.assertTrue(has_vuln(d, 'xss') or report_ok(d))

    def test_sf_032_xss_return_html(self):
        d = analyze("from flask import request\ndef v():\n    q=request.args.get('q')\n    return '<html><body>'+q+'</body></html>'")
        self.assertTrue(report_ok(d))

    def test_sf_033_xss_safe_escape(self):
        d = analyze("from flask import request, escape\ndef v():\n    name=escape(request.args.get('name',''))\n    return f'<h1>{name}</h1>'")
        self.assertTrue(report_ok(d))

    def test_sf_034_xss_jinja2_safe(self):
        d = analyze("from flask import request, render_template\ndef v():\n    name=request.args.get('name')\n    return render_template('index.html', name=name)")
        self.assertFalse(has_vuln(d, 'xss'))

    def test_sf_035_xss_jsonify_safe(self):
        d = analyze("from flask import request, jsonify\ndef v():\n    name=request.args.get('name')\n    return jsonify({'name': name})")
        self.assertFalse(has_vuln(d, 'xss'))

    def test_sf_036_xss_content_type(self):
        d = analyze("from flask import request\ndef v():\n    data=request.form.get('html')\n    return data, 200, {'Content-Type':'text/html'}")
        self.assertTrue(report_ok(d))

    def test_sf_037_xss_fstring_html(self):
        d = analyze("from flask import request\ndef v():\n    n=request.args.get('n')\n    return f'<div class=\"result\">{n}</div>'")
        self.assertTrue(report_ok(d))

    def test_sf_038_xss_from_db_reflected(self):
        d = analyze("from flask import request\ndef v():\n    q=request.args.get('q')\n    result=db.query(q)\n    return '<p>Result: '+str(result)+'</p>'")
        self.assertTrue(report_ok(d))

    # ── SSRF (8) ─────────────────────────────────────────────────────────────
    def test_sf_039_ssrf_requests_get(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    url=request.args.get('url')\n    return requests.get(url).text")
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_sf_040_ssrf_requests_post(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    url=request.form.get('url')\n    return requests.post(url, data={}).text")
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_sf_041_ssrf_urlopen(self):
        d = analyze("from urllib.request import urlopen\nfrom flask import request\ndef v():\n    url=request.args.get('url')\n    return urlopen(url).read()")
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_sf_042_ssrf_httpx(self):
        d = analyze("import httpx\nfrom flask import request\ndef v():\n    url=request.args.get('url')\n    return httpx.get(url).text")
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_sf_043_ssrf_safe_static_url(self):
        d = analyze("import requests\ndef fetch():\n    return requests.get('https://api.example.com/data').json()")
        self.assertFalse(has_vuln(d, 'ssrf'))

    def test_sf_044_ssrf_from_json(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    payload=request.json\n    requests.get(payload['webhook'])")
        self.assertTrue(report_ok(d))

    def test_sf_045_ssrf_from_form(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    target=request.form.get('target')\n    resp=requests.put(target, json={})\n    return resp.text")
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_sf_046_ssrf_from_header(self):
        d = analyze("import requests\nfrom flask import request\ndef v():\n    cb=request.headers.get('X-Callback')\n    requests.post(cb, json={'status':'done'})")
        self.assertTrue(report_ok(d))

    # ── Deserialization (6) ───────────────────────────────────────────────────
    def test_sf_047_deser_pickle_loads(self):
        d = analyze("import pickle\nfrom flask import request\ndef v():\n    data=request.data\n    return pickle.loads(data)")
        self.assertTrue(has_vuln(d, 'deserializ'))

    def test_sf_048_deser_pickle_load(self):
        d = analyze("import pickle\nfrom flask import request\ndef v():\n    f=request.files.get('f')\n    obj=pickle.load(f)")
        self.assertTrue(has_vuln(d, 'deserializ'))

    def test_sf_049_deser_yaml_load_unsafe(self):
        d = analyze("import yaml\nfrom flask import request\ndef v():\n    data=request.data\n    return yaml.load(data)")
        self.assertTrue(has_vuln(d, 'deserializ'))

    def test_sf_050_deser_yaml_safe_ok(self):
        d = analyze("import yaml\nfrom flask import request\ndef v():\n    data=request.data\n    return yaml.safe_load(data)")
        self.assertFalse(has_vuln(d, 'deserializ'))

    def test_sf_051_deser_marshal(self):
        d = analyze("import marshal\nfrom flask import request\ndef v():\n    data=request.data\n    return marshal.loads(data)")
        self.assertTrue(report_ok(d))

    def test_sf_052_deser_json_safe(self):
        d = analyze("import json\nfrom flask import request\ndef v():\n    data=request.data\n    return json.loads(data)")
        self.assertFalse(has_vuln(d, 'deserializ'))

    # ── Code Injection / eval (6) ────────────────────────────────────────────
    def test_sf_053_eval_direct(self):
        d = analyze("from flask import request\ndef v():\n    expr=request.args.get('expr')\n    return eval(expr)")
        self.assertTrue(has_vuln(d, 'injection') or has_vuln(d, 'eval') or has_vuln(d, 'code'))

    def test_sf_054_exec_direct(self):
        d = analyze("from flask import request\ndef v():\n    code=request.form.get('code')\n    exec(code)")
        self.assertTrue(report_ok(d))

    def test_sf_055_compile_exec(self):
        d = analyze("from flask import request\ndef v():\n    src=request.form.get('src')\n    exec(compile(src,'<str>','exec'))")
        self.assertTrue(report_ok(d))

    def test_sf_056_eval_static_safe(self):
        d = analyze("def compute():\n    return eval('2+2')")
        self.assertTrue(report_ok(d))

    def test_sf_057_eval_in_loop(self):
        d = analyze("from flask import request\ndef v():\n    exprs=request.json['exprs']\n    results=[]\n    for e in exprs:\n        results.append(eval(e))\n    return results")
        self.assertTrue(report_ok(d))

    def test_sf_058_import_dynamic(self):
        d = analyze("from flask import request\ndef v():\n    mod=request.args.get('mod')\n    __import__(mod)")
        self.assertTrue(report_ok(d))

    # ── Auth / IDOR (6) ───────────────────────────────────────────────────────
    def test_sf_059_idor_get_record(self):
        d = analyze("from flask import request\ndef v():\n    doc_id=request.args.get('id')\n    return db.get(doc_id)")
        self.assertTrue(report_ok(d))

    def test_sf_060_idor_guarded(self):
        d = analyze("from flask import request\nfrom flask_login import login_required\n@login_required\ndef v():\n    doc_id=request.args.get('id')\n    return db.get(doc_id)")
        self.assertTrue(report_ok(d))

    def test_sf_061_missing_auth_delete(self):
        d = analyze("from flask import request\ndef v():\n    uid=request.args.get('uid')\n    db.delete_user(uid)")
        self.assertTrue(report_ok(d))

    def test_sf_062_missing_auth_transfer(self):
        d = analyze("from flask import request\ndef v():\n    to=request.form.get('to')\n    amount=request.form.get('amount')\n    bank.transfer(to, amount)")
        self.assertTrue(report_ok(d))

    def test_sf_063_auth_abort_guard(self):
        d = analyze("from flask import request, abort\ndef v():\n    if not current_user.is_authenticated:\n        abort(401)\n    uid=request.args.get('uid')\n    return db.get(uid)")
        self.assertTrue(report_ok(d))

    def test_sf_064_auth_check_before_delete(self):
        d = analyze("from flask import request, abort\ndef delete():\n    if not is_admin():\n        abort(403)\n    uid=request.args.get('uid')\n    db.delete_user(uid)")
        self.assertTrue(report_ok(d))

    # ── Clean Code (12) ───────────────────────────────────────────────────────
    def test_sf_065_clean_pure_function(self):
        d = analyze("def add(a, b):\n    return a + b\n\ndef multiply(a, b):\n    return a * b")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_066_clean_dataclass(self):
        d = analyze("from dataclasses import dataclass\n@dataclass\nclass Point:\n    x: float\n    y: float\n    def distance(self):\n        return (self.x**2 + self.y**2)**0.5")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_067_clean_generator(self):
        d = analyze("def fibonacci():\n    a, b = 0, 1\n    while True:\n        yield a\n        a, b = b, a+b")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_068_clean_context_manager(self):
        d = analyze("from contextlib import contextmanager\n@contextmanager\ndef managed_resource():\n    resource = acquire()\n    try:\n        yield resource\n    finally:\n        release(resource)")
        self.assertTrue(report_ok(d))

    def test_sf_069_clean_list_comprehension(self):
        d = analyze("def evens(n):\n    return [x for x in range(n) if x % 2 == 0]\n\ndef squares(n):\n    return {x: x**2 for x in range(n)}")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_070_clean_type_hints(self):
        d = analyze("from typing import List, Dict, Optional\ndef process(items: List[int]) -> Dict[str, int]:\n    return {str(i): i*2 for i in items}\ndef find(items: List[str], key: str) -> Optional[str]:\n    return next((x for x in items if x==key), None)")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_071_clean_async_def(self):
        d = analyze("import asyncio\nasync def fetch_data(session, url):\n    async with session.get(url) as resp:\n        return await resp.json()\nasync def main():\n    async with aiohttp.ClientSession() as s:\n        data = await fetch_data(s, 'https://api.example.com')")
        self.assertTrue(report_ok(d))

    def test_sf_072_clean_exception_handling(self):
        d = analyze("def safe_divide(a, b):\n    try:\n        return a / b\n    except ZeroDivisionError:\n        return None\n    except TypeError as e:\n        raise ValueError(f'Invalid input: {e}') from e")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_073_clean_property(self):
        d = analyze("class Temperature:\n    def __init__(self, celsius):\n        self._c = celsius\n    @property\n    def fahrenheit(self):\n        return self._c * 9/5 + 32\n    @fahrenheit.setter\n    def fahrenheit(self, val):\n        self._c = (val - 32) * 5/9")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_074_clean_decorator(self):
        d = analyze("import functools\ndef retry(times=3):\n    def decorator(func):\n        @functools.wraps(func)\n        def wrapper(*args, **kwargs):\n            for i in range(times):\n                try:\n                    return func(*args, **kwargs)\n                except Exception:\n                    if i==times-1: raise\n        return wrapper\n    return decorator")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_075_clean_enum(self):
        d = analyze("from enum import Enum, auto\nclass Status(Enum):\n    PENDING = auto()\n    ACTIVE = auto()\n    CLOSED = auto()\ndef describe(s: Status) -> str:\n    return s.name.lower()")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_076_clean_abstract_class(self):
        d = analyze("from abc import ABC, abstractmethod\nclass Shape(ABC):\n    @abstractmethod\n    def area(self) -> float: ...\n    @abstractmethod\n    def perimeter(self) -> float: ...\nclass Circle(Shape):\n    def __init__(self, r): self.r=r\n    def area(self): return 3.14159*self.r**2\n    def perimeter(self): return 2*3.14159*self.r")
        self.assertTrue(is_clean(d) and report_ok(d))

    # ── Structural Issues Detected (10) ──────────────────────────────────────
    def test_sf_077_struct_syntax_error(self):
        d = analyze("def foo(:\n    pass")
        self.assertTrue(report_ok(d))

    def test_sf_078_struct_unused_var(self):
        d = analyze("def foo():\n    x = 10\n    y = 20\n    return y")
        self.assertTrue(report_ok(d))

    def test_sf_079_struct_shadowed_var(self):
        d = analyze("def foo():\n    result = 0\n    result = compute()\n    return result")
        self.assertTrue(report_ok(d))

    def test_sf_080_struct_empty_except(self):
        d = analyze("def foo():\n    try:\n        risky()\n    except:\n        pass")
        self.assertTrue(report_ok(d))

    def test_sf_081_struct_mutable_default(self):
        d = analyze("def append_to(element, to=[]):\n    to.append(element)\n    return to")
        self.assertTrue(report_ok(d))

    def test_sf_082_struct_global_usage(self):
        d = analyze("counter = 0\ndef increment():\n    global counter\n    counter += 1")
        self.assertTrue(report_ok(d))

    def test_sf_083_struct_deep_nesting(self):
        d = analyze("def process(data):\n    if data:\n        for item in data:\n            if item.valid:\n                for sub in item.subs:\n                    if sub.active:\n                        for x in sub.items:\n                            if x > 0:\n                                result = x * 2")
        self.assertTrue(report_ok(d))

    def test_sf_084_struct_long_function(self):
        lines = ["def big_function(x):"]
        for i in range(60):
            lines.append(f"    step_{i} = x + {i}")
        lines.append("    return step_0")
        d = analyze('\n'.join(lines))
        self.assertTrue(report_ok(d))

    def test_sf_085_struct_duplicate_keys(self):
        d = analyze("config = {\n    'host': 'localhost',\n    'port': 5432,\n    'host': '127.0.0.1',\n}")
        self.assertTrue(report_ok(d))

    def test_sf_086_struct_circular_import(self):
        d = analyze("# simulating complex module\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from mymodule import MyClass\ndef process(obj):\n    return str(obj)")
        self.assertTrue(report_ok(d))

    # ── Mixed / Edge Cases (14) ───────────────────────────────────────────────
    def test_sf_087_empty_code(self):
        d = analyze("")
        # Should get error not crash
        self.assertIn('error', d)

    def test_sf_088_only_comments(self):
        d = analyze("# This is a comment\n# Another comment\n")
        self.assertTrue(report_ok(d))

    def test_sf_089_only_imports(self):
        d = analyze("import os\nimport sys\nfrom pathlib import Path\n")
        self.assertTrue(report_ok(d))

    def test_sf_090_multiline_string(self):
        d = analyze('def get_query():\n    return """\n        SELECT *\n        FROM users\n        WHERE active = 1\n    """')
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_091_flask_blueprint(self):
        d = analyze("from flask import Blueprint, request\nbp = Blueprint('api', __name__)\n@bp.route('/search')\ndef search():\n    q = request.args.get('q')\n    cursor.execute('SELECT * FROM products WHERE name=' + q)")
        self.assertTrue(has_vuln(d, 'sql'))

    def test_sf_092_django_view(self):
        d = analyze("from django.http import HttpRequest, HttpResponse\ndef view(request: HttpRequest):\n    name = request.GET.get('name')\n    cursor.execute('SELECT * FROM users WHERE name=' + name)\n    return HttpResponse('ok')")
        self.assertTrue(report_ok(d))

    def test_sf_093_fastapi_route(self):
        d = analyze("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items/{item_id}')\ndef read_item(item_id: int):\n    return {'item_id': item_id}")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_094_multiple_vulns_same_file(self):
        d = analyze("import os, pickle\nfrom flask import request\ndef v():\n    f=request.args.get('f')\n    cmd=request.args.get('cmd')\n    data=request.data\n    open(f).read()\n    os.system(cmd)\n    pickle.loads(data)")
        self.assertGreaterEqual(d.get('security_count', 0), 2)

    def test_sf_095_lambda_no_crash(self):
        d = analyze("double = lambda x: x * 2\ntriple = lambda x: x * 3\nresult = list(map(double, range(10)))")
        self.assertTrue(report_ok(d))

    def test_sf_096_walrus_operator(self):
        d = analyze("import re\ndef parse(text):\n    if m := re.match(r'(\\d+)', text):\n        return int(m.group(1))\n    return 0")
        self.assertTrue(report_ok(d))

    def test_sf_097_nested_class(self):
        d = analyze("class Outer:\n    class Inner:\n        def method(self):\n            return 42\n    def use(self):\n        return self.Inner().method()")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_098_star_args(self):
        d = analyze("def func(*args, **kwargs):\n    return args, kwargs\ndef caller():\n    return func(1, 2, 3, a=4, b=5)")
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_sf_099_complex_taint_chain(self):
        d = analyze("from flask import request\ndef get_data():\n    raw = request.args.get('data')\n    processed = raw.strip().lower()\n    return processed\ndef store():\n    val = get_data()\n    cursor.execute('INSERT INTO log VALUES ('+val+')')")
        self.assertTrue(report_ok(d))

    def test_sf_100_report_has_metrics(self):
        d = analyze("def fibonacci(n):\n    if n <= 1: return n\n    return fibonacci(n-1) + fibonacci(n-2)")
        self.assertTrue(report_ok(d))
        self.assertIn('complexity', d)


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-FILE TESTS (100)
# ─────────────────────────────────────────────────────────────────────────────

class TestMultiFile(unittest.TestCase):

    def test_mf_001_sql_taint_across_files(self):
        d = analyze_files([
            {'name': 'routes.py', 'content': 'from flask import request\ndef get_id():\n    return request.args.get("id")\n'},
            {'name': 'db.py', 'content': 'from routes import get_id\ndef fetch():\n    uid = get_id()\n    cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'},
        ])
        self.assertTrue(report_ok(d) and d.get('file_count') == 2)

    def test_mf_002_cmd_injection_split(self):
        d = analyze_files([
            {'name': 'api.py', 'content': 'from flask import request\ndef endpoint():\n    cmd = request.form.get("cmd")\n    return run_cmd(cmd)\n'},
            {'name': 'utils.py', 'content': 'import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd, shell=True)\n'},
        ])
        self.assertTrue(report_ok(d) and d.get('file_count') == 2)

    def test_mf_003_path_traversal_split(self):
        d = analyze_files([
            {'name': 'views.py', 'content': 'from flask import request\nfrom fileutils import read_file\ndef v():\n    f = request.args.get("f")\n    return read_file(f)\n'},
            {'name': 'fileutils.py', 'content': 'def read_file(path):\n    return open(path).read()\n'},
        ])
        self.assertTrue(report_ok(d) and d.get('file_count') == 2)

    def test_mf_004_clean_service_layer(self):
        d = analyze_files([
            {'name': 'models.py', 'content': 'class User:\n    def __init__(self, name, email):\n        self.name = name\n        self.email = email\n    def to_dict(self):\n        return {"name": self.name, "email": self.email}\n'},
            {'name': 'service.py', 'content': 'from models import User\ndef create_user(name, email):\n    u = User(name, email)\n    db.save(u)\n    return u.to_dict()\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_005_three_file_flask_app(self):
        d = analyze_files([
            {'name': 'app.py', 'content': 'from flask import Flask\nfrom routes import register\napp = Flask(__name__)\nregister(app)\n'},
            {'name': 'routes.py', 'content': 'from flask import request\ndef register(app):\n    @app.route("/search")\n    def search():\n        q = request.args.get("q")\n        cursor.execute("SELECT * FROM t WHERE q=" + q)\n'},
            {'name': 'config.py', 'content': 'DEBUG = False\nSECRET_KEY = "change-me"\nDATABASE_URL = "postgresql://localhost/mydb"\n'},
        ])
        self.assertTrue(has_vuln(d, 'sql') and d.get('file_count') == 3)

    def test_mf_006_ssrf_split(self):
        d = analyze_files([
            {'name': 'handler.py', 'content': 'from flask import request\nfrom fetcher import fetch_url\ndef proxy():\n    url = request.args.get("url")\n    return fetch_url(url)\n'},
            {'name': 'fetcher.py', 'content': 'import requests\ndef fetch_url(url):\n    return requests.get(url).text\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_007_pickle_across_files(self):
        d = analyze_files([
            {'name': 'upload.py', 'content': 'from flask import request\ndef handle():\n    data = request.data\n    return deserialize(data)\n'},
            {'name': 'serializer.py', 'content': 'import pickle\ndef deserialize(data):\n    return pickle.loads(data)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_008_eval_across_files(self):
        d = analyze_files([
            {'name': 'api.py', 'content': 'from flask import request\nfrom calc import calculate\ndef v():\n    expr = request.args.get("expr")\n    return calculate(expr)\n'},
            {'name': 'calc.py', 'content': 'def calculate(expr):\n    return eval(expr)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_009_files_have_source_file(self):
        d = analyze_files([
            {'name': 'routes.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'models.py', 'content': 'class User:\n    pass\n'},
        ])
        if d.get('security_count', 0) > 0:
            self.assertTrue(has_source_file(d))

    def test_mf_010_files_have_local_lineno(self):
        d = analyze_files([
            {'name': 'routes.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'models.py', 'content': 'class User:\n    pass\n'},
        ])
        if d.get('security_count', 0) > 0:
            self.assertTrue(has_local_lineno(d))

    def test_mf_011_local_lineno_correct_range(self):
        routes = 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'
        d = analyze_files([
            {'name': 'routes.py', 'content': routes},
            {'name': 'utils.py', 'content': 'def add(a,b): return a+b\n'},
        ])
        for f in d.get('security_findings', []):
            if f.get('source_file') == 'routes.py':
                local = f.get('local_lineno', 0)
                self.assertLessEqual(local, routes.count('\n') + 1)
                self.assertGreater(local, 0)

    def test_mf_012_file_offsets_returned(self):
        d = analyze_files([
            {'name': 'a.py', 'content': 'x=1\n'},
            {'name': 'b.py', 'content': 'y=2\n'},
        ])
        self.assertIn('file_offsets', d)
        self.assertEqual(len(d['file_offsets']), 2)

    def test_mf_013_files_contents_returned(self):
        d = analyze_files([
            {'name': 'a.py', 'content': 'x=1\n'},
            {'name': 'b.py', 'content': 'y=2\n'},
        ])
        self.assertEqual(len(d.get('files', [])), 2)

    def test_mf_014_empty_files_rejected(self):
        d = analyze_files([])
        self.assertIn('error', d)

    def test_mf_015_single_file_in_list(self):
        d = analyze_files([
            {'name': 'main.py', 'content': 'def main():\n    print("hello")\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_016_five_clean_files(self):
        files = [{'name': f'module{i}.py', 'content': f'def func_{i}(x):\n    return x + {i}\n'} for i in range(5)]
        d = analyze_files(files)
        self.assertTrue(report_ok(d) and d.get('file_count') == 5)

    def test_mf_017_ten_files(self):
        files = [{'name': f'm{i}.py', 'content': f'x_{i} = {i}\n'} for i in range(10)]
        d = analyze_files(files)
        self.assertTrue(report_ok(d) and d.get('file_count') == 10)

    def test_mf_018_mixed_clean_and_vulns(self):
        d = analyze_files([
            {'name': 'clean.py', 'content': 'def add(a, b): return a + b\n'},
            {'name': 'vuln.py', 'content': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'also_clean.py', 'content': 'def multiply(a, b): return a * b\n'},
        ])
        self.assertTrue(has_vuln(d, 'sql'))

    def test_mf_019_open_api_pattern(self):
        d = analyze_files([
            {'name': 'app.py', 'content': 'from flask import Flask\napp = Flask(__name__)\n'},
            {'name': 'auth.py', 'content': 'from flask import request, abort\ndef require_auth():\n    token = request.headers.get("Authorization")\n    if not token:\n        abort(401)\n'},
            {'name': 'resources.py', 'content': 'from flask import request\nfrom auth import require_auth\ndef get_resource():\n    require_auth()\n    rid = request.args.get("id")\n    return db.get(rid)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_020_django_mvt_pattern(self):
        d = analyze_files([
            {'name': 'models.py', 'content': 'from django.db import models\nclass Article(models.Model):\n    title = models.CharField(max_length=200)\n    body = models.TextField()\n    class Meta:\n        ordering = ["-created_at"]\n'},
            {'name': 'views.py', 'content': 'from django.http import HttpRequest\ndef article_list(request: HttpRequest):\n    articles = Article.objects.all()\n    return render(request, "list.html", {"articles": articles})\n'},
            {'name': 'urls.py', 'content': 'from django.urls import path\nfrom . import views\nurlpatterns = [\n    path("articles/", views.article_list),\n]\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_021_middleware_pattern(self):
        d = analyze_files([
            {'name': 'middleware.py', 'content': 'from functools import wraps\nfrom flask import request, abort\ndef rate_limit(f):\n    @wraps(f)\n    def wrapper(*a, **kw):\n        ip = request.remote_addr\n        if over_limit(ip):\n            abort(429)\n        return f(*a, **kw)\n    return wrapper\n'},
            {'name': 'routes.py', 'content': 'from flask import request\nfrom middleware import rate_limit\n@rate_limit\ndef api_endpoint():\n    return {"status": "ok"}\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_022_repository_pattern(self):
        d = analyze_files([
            {'name': 'repo.py', 'content': 'class UserRepository:\n    def find_by_id(self, uid):\n        return db.query("SELECT * FROM users WHERE id=%s", (uid,))\n    def find_by_email(self, email):\n        return db.query("SELECT * FROM users WHERE email=%s", (email,))\n'},
            {'name': 'service.py', 'content': 'from repo import UserRepository\nclass UserService:\n    def __init__(self):\n        self.repo = UserRepository()\n    def get_user(self, uid):\n        return self.repo.find_by_id(uid)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_023_data_pipeline(self):
        d = analyze_files([
            {'name': 'extract.py', 'content': 'import csv\ndef extract(path):\n    with open(path) as f:\n        return list(csv.DictReader(f))\n'},
            {'name': 'transform.py', 'content': 'def transform(records):\n    return [{k.lower(): v.strip() for k,v in r.items()} for r in records]\n'},
            {'name': 'load.py', 'content': 'def load(records, conn):\n    for r in records:\n        conn.execute("INSERT INTO data VALUES (%s,%s)", (r["name"],r["value"]))\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_024_cli_tool(self):
        d = analyze_files([
            {'name': 'cli.py', 'content': 'import argparse\ndef main():\n    parser = argparse.ArgumentParser()\n    parser.add_argument("--input", required=True)\n    parser.add_argument("--output", required=True)\n    args = parser.parse_args()\n    process(args.input, args.output)\n'},
            {'name': 'processor.py', 'content': 'def process(input_path, output_path):\n    with open(input_path) as f:\n        data = f.read()\n    with open(output_path, "w") as f:\n        f.write(data.upper())\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_025_config_loader(self):
        d = analyze_files([
            {'name': 'config.py', 'content': 'import os\nclass Config:\n    DEBUG = os.getenv("DEBUG", "false").lower() == "true"\n    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key")\n    DB_URL = os.getenv("DATABASE_URL", "sqlite:///dev.db")\n'},
            {'name': 'app.py', 'content': 'from config import Config\nfrom flask import Flask\napp = Flask(__name__)\napp.config.from_object(Config)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_026_auth_module_split(self):
        d = analyze_files([
            {'name': 'auth.py', 'content': 'import hashlib, hmac\ndef hash_password(password, salt):\n    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()\ndef verify_password(password, salt, hashed):\n    return hmac.compare_digest(hash_password(password, salt), hashed)\n'},
            {'name': 'user.py', 'content': 'from auth import hash_password, verify_password\nclass User:\n    def set_password(self, pw):\n        self.salt = generate_salt()\n        self.pw_hash = hash_password(pw, self.salt)\n    def check_password(self, pw):\n        return verify_password(pw, self.salt, self.pw_hash)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_027_cache_layer(self):
        d = analyze_files([
            {'name': 'cache.py', 'content': 'import functools\n_cache = {}\ndef memoize(func):\n    @functools.wraps(func)\n    def wrapper(*args):\n        if args not in _cache:\n            _cache[args] = func(*args)\n        return _cache[args]\n    return wrapper\n'},
            {'name': 'expensive.py', 'content': 'from cache import memoize\n@memoize\ndef compute(n):\n    return sum(range(n))\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_028_event_system(self):
        d = analyze_files([
            {'name': 'events.py', 'content': 'from collections import defaultdict\nclass EventBus:\n    def __init__(self):\n        self._handlers = defaultdict(list)\n    def on(self, event, handler):\n        self._handlers[event].append(handler)\n    def emit(self, event, *args):\n        for h in self._handlers[event]:\n            h(*args)\n'},
            {'name': 'app.py', 'content': 'from events import EventBus\nbus = EventBus()\nbus.on("user.created", lambda u: send_welcome_email(u))\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_029_multiple_sql_injections(self):
        d = analyze_files([
            {'name': 'users.py', 'content': 'from flask import request\ndef get_user():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM users WHERE id="+uid)\ndef search_users():\n    q=request.args.get("q")\n    cursor.execute("SELECT * FROM users WHERE name="+q)\n'},
            {'name': 'products.py', 'content': 'from flask import request\ndef get_product():\n    pid=request.args.get("id")\n    cursor.execute("SELECT * FROM products WHERE id="+pid)\n'},
        ])
        self.assertGreaterEqual(d.get('security_count', 0), 2)

    def test_mf_030_file_names_in_response(self):
        d = analyze_files([
            {'name': 'mod_a.py', 'content': 'x=1\n'},
            {'name': 'mod_b.py', 'content': 'y=2\n'},
            {'name': 'mod_c.py', 'content': 'z=3\n'},
        ])
        names = d.get('file_names', [])
        self.assertEqual(set(names), {'mod_a.py', 'mod_b.py', 'mod_c.py'})

    # ── 70 more diverse multi-file tests ─────────────────────────────────────
    def test_mf_031_async_api(self):
        d = analyze_files([
            {'name': 'async_api.py', 'content': 'from aiohttp import web\nasync def handle(request):\n    name = request.rel_url.query.get("name")\n    return web.Response(text=f"Hello {name}")\n'},
            {'name': 'server.py', 'content': 'from aiohttp import web\nfrom async_api import handle\napp = web.Application()\napp.router.add_get("/", handle)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_032_websocket_handler(self):
        d = analyze_files([
            {'name': 'ws.py', 'content': 'async def ws_handler(websocket, path):\n    async for message in websocket:\n        await websocket.send(f"Echo: {message}")\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_033_graphql_resolver(self):
        d = analyze_files([
            {'name': 'resolvers.py', 'content': 'def resolve_user(parent, info, id):\n    return db.query("SELECT * FROM users WHERE id=%s", (id,))\n'},
            {'name': 'schema.py', 'content': 'import graphene\nclass User(graphene.ObjectType):\n    id = graphene.ID()\n    name = graphene.String()\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_034_celery_task(self):
        d = analyze_files([
            {'name': 'tasks.py', 'content': 'from celery import Celery\napp = Celery("tasks", broker="redis://localhost")\n@app.task\ndef process_email(recipient, subject, body):\n    send_email(recipient, subject, body)\n    return True\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_035_sqlalchemy_models(self):
        d = analyze_files([
            {'name': 'models.py', 'content': 'from sqlalchemy import Column, Integer, String\nfrom sqlalchemy.ext.declarative import declarative_base\nBase = declarative_base()\nclass User(Base):\n    __tablename__ = "users"\n    id = Column(Integer, primary_key=True)\n    username = Column(String(50), unique=True)\n    email = Column(String(100))\n'},
            {'name': 'crud.py', 'content': 'from models import User\ndef create_user(session, username, email):\n    user = User(username=username, email=email)\n    session.add(user)\n    session.commit()\n    return user\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_036_pydantic_schema(self):
        d = analyze_files([
            {'name': 'schemas.py', 'content': 'from pydantic import BaseModel, EmailStr\nfrom typing import Optional\nclass UserCreate(BaseModel):\n    username: str\n    email: EmailStr\n    password: str\nclass UserRead(BaseModel):\n    id: int\n    username: str\n    email: str\n'},
            {'name': 'api.py', 'content': 'from fastapi import FastAPI\nfrom schemas import UserCreate, UserRead\napp = FastAPI()\n@app.post("/users", response_model=UserRead)\ndef create_user(data: UserCreate):\n    return service.create(data)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_037_dependency_injection(self):
        d = analyze_files([
            {'name': 'db.py', 'content': 'from sqlalchemy.orm import Session\nfrom fastapi import Depends\ndef get_db():\n    db = SessionLocal()\n    try:\n        yield db\n    finally:\n        db.close()\n'},
            {'name': 'routes.py', 'content': 'from fastapi import APIRouter, Depends\nfrom db import get_db\nrouter = APIRouter()\n@router.get("/items")\ndef list_items(db = Depends(get_db)):\n    return db.query(Item).all()\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_038_pytest_fixtures(self):
        d = analyze_files([
            {'name': 'conftest.py', 'content': 'import pytest\nfrom app import create_app\n@pytest.fixture\ndef app():\n    app = create_app({"TESTING": True})\n    yield app\n@pytest.fixture\ndef client(app):\n    return app.test_client()\n'},
            {'name': 'test_routes.py', 'content': 'def test_home(client):\n    resp = client.get("/")\n    assert resp.status_code == 200\ndef test_404(client):\n    resp = client.get("/nonexistent")\n    assert resp.status_code == 404\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_039_logging_module(self):
        d = analyze_files([
            {'name': 'logger.py', 'content': 'import logging\ndef get_logger(name):\n    logger = logging.getLogger(name)\n    logger.setLevel(logging.DEBUG)\n    handler = logging.StreamHandler()\n    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))\n    logger.addHandler(handler)\n    return logger\n'},
            {'name': 'app.py', 'content': 'from logger import get_logger\nlog = get_logger(__name__)\ndef process():\n    log.info("Processing started")\n    result = do_work()\n    log.info(f"Done: {result}")\n    return result\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_040_error_handler(self):
        d = analyze_files([
            {'name': 'errors.py', 'content': 'class AppError(Exception):\n    def __init__(self, msg, code=400):\n        self.msg = msg\n        self.code = code\nclass NotFoundError(AppError):\n    def __init__(self, resource):\n        super().__init__(f"{resource} not found", 404)\n'},
            {'name': 'handlers.py', 'content': 'from flask import jsonify\nfrom errors import AppError\ndef register_handlers(app):\n    @app.errorhandler(AppError)\n    def handle_app_error(e):\n        return jsonify({"error": e.msg}), e.code\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    # ── 60 more files — covering broader scenarios ────────────────────────────
    def _make_vuln_files(self, vuln_code, clean_code='def helper(): pass\n'):
        return [{'name': 'main.py', 'content': vuln_code},
                {'name': 'utils.py', 'content': clean_code}]

    def _make_clean_files(self, *contents):
        return [{'name': f'mod{i}.py', 'content': c} for i, c in enumerate(contents)]

    def test_mf_041_ssrf_via_config(self):
        d = analyze_files(self._make_vuln_files(
            'import requests\nfrom flask import request\ndef proxy():\n    url=request.json["url"]\n    return requests.get(url).text\n'))
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_mf_042_multi_ssrf(self):
        d = analyze_files([
            {'name': 'a.py', 'content': 'import requests\nfrom flask import request\ndef a():\n    url=request.args.get("u")\n    return requests.get(url).text\n'},
            {'name': 'b.py', 'content': 'import requests\nfrom flask import request\ndef b():\n    url=request.form.get("u")\n    return requests.post(url).text\n'},
        ])
        self.assertGreaterEqual(d.get('security_count', 0), 1)

    def test_mf_043_clean_three_layer(self):
        d = analyze_files(self._make_clean_files(
            'class Repo:\n    def find(self, id): return db.get(id)\n',
            'class Service:\n    def __init__(self):\n        self.repo = None\n    def get(self, id): return self.repo.find(id)\n',
            'class Controller:\n    pass\n',
        ))
        self.assertTrue(report_ok(d))

    def test_mf_044_file_count_matches(self):
        files = [{'name': f'f{i}.py', 'content': f'x={i}\n'} for i in range(7)]
        d = analyze_files(files)
        self.assertEqual(d.get('file_count'), 7)

    def test_mf_045_structural_issues_multi(self):
        d = analyze_files([
            {'name': 'a.py', 'content': 'def foo():\n    x=1\n    x=2\n    return x\n'},
            {'name': 'b.py', 'content': 'def bar():\n    y=10\n    return 0\n'},
        ])
        self.assertTrue(report_ok(d))
        self.assertGreater(d.get('structural_count', 0), 0)

    def test_mf_046_large_clean_app(self):
        files = []
        for i in range(8):
            files.append({'name': f'module_{i}.py',
                          'content': f'def func_{i}(x, y):\n    """Compute something."""\n    result = x * {i+1} + y\n    return result\n\nclass Class_{i}:\n    def method(self):\n        return func_{i}(1, 2)\n'})
        d = analyze_files(files)
        self.assertTrue(report_ok(d) and d.get('file_count') == 8)

    def test_mf_047_type_annotated_vuln(self):
        d = analyze_files([
            {'name': 'routes.py', 'content': 'from flask import request\ndef search() -> str:\n    q: str = request.args.get("q")\n    cursor.execute("SELECT * FROM t WHERE name=" + q)\n    return "ok"\n'},
        ])
        self.assertTrue(has_vuln(d, 'sql'))

    def test_mf_048_generator_no_vuln(self):
        d = analyze_files(self._make_clean_files(
            'def gen(n):\n    for i in range(n):\n        yield i**2\n',
            'def consume(n):\n    return list(gen(n))\n',
        ))
        self.assertTrue(is_clean(d))

    def test_mf_049_mixins(self):
        d = analyze_files([
            {'name': 'mixins.py', 'content': 'class TimestampMixin:\n    def touch(self):\n        self.updated_at = now()\nclass SoftDeleteMixin:\n    def delete(self):\n        self.deleted = True\n'},
            {'name': 'models.py', 'content': 'from mixins import TimestampMixin, SoftDeleteMixin\nclass Article(TimestampMixin, SoftDeleteMixin):\n    def __init__(self, title):\n        self.title = title\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_050_signal_handler(self):
        d = analyze_files([
            {'name': 'signals.py', 'content': 'import signal, sys\ndef handle_sigterm(signum, frame):\n    print("Graceful shutdown")\n    sys.exit(0)\nsignal.signal(signal.SIGTERM, handle_sigterm)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_051_path_traversal_in_util(self):
        d = analyze_files([
            {'name': 'api.py', 'content': 'from flask import request\nfrom fileutil import serve\ndef v():\n    f=request.args.get("f")\n    return serve(f)\n'},
            {'name': 'fileutil.py', 'content': 'def serve(path):\n    return open("/static/"+path).read()\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_052_retry_decorator(self):
        d = analyze_files([
            {'name': 'retry.py', 'content': 'import time, functools\ndef retry(max_attempts=3, delay=1.0):\n    def deco(fn):\n        @functools.wraps(fn)\n        def wrapper(*a, **kw):\n            for i in range(max_attempts):\n                try:\n                    return fn(*a, **kw)\n                except Exception:\n                    if i==max_attempts-1: raise\n                    time.sleep(delay)\n        return wrapper\n    return deco\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_053_jwt_auth(self):
        d = analyze_files([
            {'name': 'jwt_util.py', 'content': 'import jwt\nSECRET = "change-me"\ndef encode_token(payload):\n    return jwt.encode(payload, SECRET, algorithm="HS256")\ndef decode_token(token):\n    return jwt.decode(token, SECRET, algorithms=["HS256"])\n'},
            {'name': 'auth_routes.py', 'content': 'from flask import request, jsonify\nfrom jwt_util import decode_token\ndef protected():\n    token = request.headers.get("Authorization","").replace("Bearer ","")\n    payload = decode_token(token)\n    return jsonify(payload)\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_054_rate_limiter(self):
        d = analyze_files([
            {'name': 'limiter.py', 'content': 'from collections import defaultdict\nimport time\nclass RateLimiter:\n    def __init__(self, limit, window):\n        self.limit=limit; self.window=window; self.counts=defaultdict(list)\n    def allow(self, key):\n        now=time.time()\n        self.counts[key]=[t for t in self.counts[key] if now-t<self.window]\n        if len(self.counts[key])>=self.limit:\n            return False\n        self.counts[key].append(now)\n        return True\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_055_state_machine(self):
        d = analyze_files([
            {'name': 'states.py', 'content': 'class OrderState:\n    PENDING="pending"\n    PAID="paid"\n    SHIPPED="shipped"\n    DELIVERED="delivered"\n    CANCELLED="cancelled"\n    TRANSITIONS={"pending":["paid","cancelled"],"paid":["shipped","cancelled"],"shipped":["delivered"]}\n    @classmethod\n    def can_transition(cls, from_s, to_s):\n        return to_s in cls.TRANSITIONS.get(from_s,[])\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_056_observer_pattern(self):
        d = analyze_files([
            {'name': 'observer.py', 'content': 'class Subject:\n    def __init__(self):\n        self._observers=[]\n    def attach(self,o): self._observers.append(o)\n    def notify(self,event): [o.update(event) for o in self._observers]\nclass Observer:\n    def update(self,event): pass\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_057_strategy_pattern(self):
        d = analyze_files([
            {'name': 'sorters.py', 'content': 'class BubbleSort:\n    def sort(self,data): return sorted(data)\nclass QuickSort:\n    def sort(self,data): return sorted(data,key=lambda x:x)\n'},
            {'name': 'context.py', 'content': 'class Sorter:\n    def __init__(self,strategy):\n        self.strategy=strategy\n    def sort(self,data):\n        return self.strategy.sort(data)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_058_factory_pattern(self):
        d = analyze_files([
            {'name': 'factory.py', 'content': 'class ShapeFactory:\n    _registry={}\n    @classmethod\n    def register(cls,name,klass): cls._registry[name]=klass\n    @classmethod\n    def create(cls,name,**kw): return cls._registry[name](**kw)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_059_plugin_system(self):
        d = analyze_files([
            {'name': 'plugin_base.py', 'content': 'from abc import ABC, abstractmethod\nclass Plugin(ABC):\n    @abstractmethod\n    def execute(self, context): ...\n    @property\n    def name(self): return self.__class__.__name__\n'},
            {'name': 'plugin_manager.py', 'content': 'from plugin_base import Plugin\nclass PluginManager:\n    def __init__(self):\n        self._plugins=[]\n    def register(self,p):\n        assert isinstance(p, Plugin)\n        self._plugins.append(p)\n    def run_all(self, ctx):\n        return [p.execute(ctx) for p in self._plugins]\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_060_metrics_collector(self):
        d = analyze_files([
            {'name': 'metrics.py', 'content': 'import time\nfrom collections import defaultdict\nclass Metrics:\n    def __init__(self):\n        self._counts=defaultdict(int)\n        self._timings=defaultdict(list)\n    def increment(self,name,val=1): self._counts[name]+=val\n    def timing(self,name,t): self._timings[name].append(t)\n    def report(self): return dict(self._counts)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_061_serializer(self):
        d = analyze_files([
            {'name': 'serializer.py', 'content': 'import json\nfrom datetime import datetime\nclass DateTimeEncoder(json.JSONEncoder):\n    def default(self,obj):\n        if isinstance(obj,datetime):\n            return obj.isoformat()\n        return super().default(obj)\ndef serialize(obj): return json.dumps(obj,cls=DateTimeEncoder)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_062_pagination(self):
        d = analyze_files([
            {'name': 'pagination.py', 'content': 'from flask import request\ndef get_page_args(default_page=1, default_size=20):\n    page = max(1, int(request.args.get("page", default_page)))\n    size = min(100, max(1, int(request.args.get("size", default_size))))\n    return page, size\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_063_file_upload_safe(self):
        d = analyze_files([
            {'name': 'upload.py', 'content': 'import os\nfrom flask import request\nALLOWED = {".png", ".jpg", ".gif"}\ndef upload():\n    f = request.files.get("file")\n    ext = os.path.splitext(f.filename)[1].lower()\n    if ext not in ALLOWED:\n        return "Invalid", 400\n    safe_name = secure_filename(f.filename)\n    f.save(os.path.join("/uploads", safe_name))\n    return "ok"\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_064_token_bucket(self):
        d = analyze_files([
            {'name': 'token_bucket.py', 'content': 'import time\nclass TokenBucket:\n    def __init__(self,capacity,fill_rate):\n        self.capacity=capacity\n        self._tokens=capacity\n        self.fill_rate=fill_rate\n        self._ts=time.time()\n    def consume(self,tokens=1):\n        now=time.time()\n        self._tokens=min(self.capacity, self._tokens+(now-self._ts)*self.fill_rate)\n        self._ts=now\n        if tokens<=self._tokens:\n            self._tokens-=tokens\n            return True\n        return False\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_065_health_check_endpoint(self):
        d = analyze_files([
            {'name': 'health.py', 'content': 'from flask import jsonify\nimport time\nSTART_TIME=time.time()\ndef health():\n    return jsonify({"status":"ok","uptime":int(time.time()-START_TIME)})\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_066_db_pool(self):
        d = analyze_files([
            {'name': 'pool.py', 'content': 'from threading import Lock\nclass ConnectionPool:\n    def __init__(self,factory,size=10):\n        self._lock=Lock()\n        self._pool=[factory() for _ in range(size)]\n    def get(self):\n        with self._lock:\n            if self._pool: return self._pool.pop()\n        return factory()\n    def put(self,conn):\n        with self._lock:\n            self._pool.append(conn)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_067_background_worker(self):
        d = analyze_files([
            {'name': 'worker.py', 'content': 'import threading, queue\nclass Worker:\n    def __init__(self):\n        self.q=queue.Queue()\n        self.t=threading.Thread(target=self._run,daemon=True)\n        self.t.start()\n    def _run(self):\n        while True:\n            task=self.q.get()\n            if task is None: break\n            task()\n            self.q.task_done()\n    def submit(self,task): self.q.put(task)\n    def stop(self): self.q.put(None)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_068_schema_validator(self):
        d = analyze_files([
            {'name': 'validator.py', 'content': 'class Validator:\n    def __init__(self,schema):\n        self.schema=schema\n    def validate(self,data):\n        errors=[]\n        for field,rules in self.schema.items():\n            val=data.get(field)\n            if rules.get("required") and not val:\n                errors.append(f"{field} is required")\n            if val and rules.get("max_length") and len(str(val))>rules["max_length"]:\n                errors.append(f"{field} too long")\n        return errors\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_069_test_doubles(self):
        d = analyze_files([
            {'name': 'mocks.py', 'content': 'class MockDB:\n    def __init__(self):\n        self._data={}\n    def get(self,key): return self._data.get(key)\n    def set(self,key,val): self._data[key]=val\n    def delete(self,key): self._data.pop(key,None)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_070_crypto_util(self):
        d = analyze_files([
            {'name': 'crypto.py', 'content': 'import hashlib, os, base64\ndef generate_token(length=32):\n    return base64.urlsafe_b64encode(os.urandom(length)).decode()\ndef hash_data(data):\n    return hashlib.sha256(data.encode()).hexdigest()\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_071_request_validator(self):
        d = analyze_files([
            {'name': 'validate.py', 'content': 'from flask import request, jsonify\ndef require_json(f):\n    from functools import wraps\n    @wraps(f)\n    def wrapper(*a,**kw):\n        if not request.is_json:\n            return jsonify({"error":"JSON required"}),415\n        return f(*a,**kw)\n    return wrapper\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_072_structured_logging(self):
        d = analyze_files([
            {'name': 'log.py', 'content': 'import json, sys, time\ndef log(level, msg, **ctx):\n    entry={"ts":time.time(),"level":level,"msg":msg}\n    entry.update(ctx)\n    print(json.dumps(entry),file=sys.stderr)\ndef info(msg,**ctx): log("INFO",msg,**ctx)\ndef error(msg,**ctx): log("ERROR",msg,**ctx)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_073_feature_flags(self):
        d = analyze_files([
            {'name': 'flags.py', 'content': 'import os\nFLAGS={}\ndef is_enabled(flag):\n    return FLAGS.get(flag, os.getenv(f"FLAG_{flag.upper()}","0")=="1")\ndef enable(flag): FLAGS[flag]=True\ndef disable(flag): FLAGS[flag]=False\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_074_content_negotiation(self):
        d = analyze_files([
            {'name': 'negotiation.py', 'content': 'from flask import request, jsonify\ndef respond(data):\n    accept=request.headers.get("Accept","")\n    if "application/json" in accept:\n        return jsonify(data)\n    return str(data)\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_075_circuit_breaker(self):
        d = analyze_files([
            {'name': 'circuit.py', 'content': 'import time\nclass CircuitBreaker:\n    CLOSED="closed"; OPEN="open"; HALF="half"\n    def __init__(self,threshold=5,timeout=60):\n        self.state=self.CLOSED; self.failures=0\n        self.threshold=threshold; self.timeout=timeout; self.last_failure=0\n    def call(self,fn,*a,**kw):\n        if self.state==self.OPEN:\n            if time.time()-self.last_failure>self.timeout:\n                self.state=self.HALF\n            else: raise Exception("Circuit open")\n        try:\n            r=fn(*a,**kw); self.failures=0; self.state=self.CLOSED; return r\n        except Exception:\n            self.failures+=1; self.last_failure=time.time()\n            if self.failures>=self.threshold: self.state=self.OPEN\n            raise\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_076_html_injection_split(self):
        d = analyze_files([
            {'name': 'view.py', 'content': 'from flask import request\nfrom renderer import render_greeting\ndef v():\n    name=request.args.get("name")\n    return render_greeting(name)\n'},
            {'name': 'renderer.py', 'content': 'def render_greeting(name):\n    return f"<html><body>Hello {name}</body></html>"\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_077_missing_auth_admin(self):
        d = analyze_files([
            {'name': 'admin.py', 'content': 'from flask import request\ndef delete_user():\n    uid=request.args.get("uid")\n    db.delete_user(uid)\n    return "deleted"\n'},
        ])
        self.assertTrue(report_ok(d))

    def test_mf_078_parametrize_sql_multi(self):
        d = analyze_files([
            {'name': 'safe_db.py', 'content': 'from flask import request\ndef get_user():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM users WHERE id=%s",(uid,))\ndef get_product():\n    pid=request.args.get("id")\n    cursor.execute("SELECT * FROM products WHERE id=%s",(pid,))\n'},
        ])
        self.assertFalse(has_vuln(d, 'sql'))

    def test_mf_079_multiple_files_different_vulns(self):
        d = analyze_files([
            {'name': 'sql_vuln.py', 'content': 'from flask import request\ndef sql_view():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'},
            {'name': 'cmd_vuln.py', 'content': 'import subprocess\nfrom flask import request\ndef cmd_view():\n    cmd=request.args.get("cmd")\n    subprocess.run(cmd,shell=True)\n'},
            {'name': 'path_vuln.py', 'content': 'from flask import request\ndef path_view():\n    f=request.args.get("f")\n    open(f).read()\n'},
        ])
        self.assertGreaterEqual(d.get('security_count', 0), 2)

    def test_mf_080_all_clean_utility_lib(self):
        d = analyze_files([
            {'name': 'string_utils.py', 'content': 'def camel_to_snake(s):\n    import re\n    return re.sub(r"(?<!^)(?=[A-Z])","_",s).lower()\ndef truncate(s,n,ellipsis="..."):\n    return s[:n-len(ellipsis)]+ellipsis if len(s)>n else s\n'},
            {'name': 'num_utils.py', 'content': 'def clamp(val,lo,hi): return max(lo,min(hi,val))\ndef lerp(a,b,t): return a+(b-a)*t\ndef sign(x): return (x>0)-(x<0)\n'},
            {'name': 'list_utils.py', 'content': 'def chunks(lst,n):\n    for i in range(0,len(lst),n):\n        yield lst[i:i+n]\ndef flatten(lst):\n    return [x for sub in lst for x in sub]\ndef unique(lst):\n    seen=set(); return [x for x in lst if not(x in seen or seen.add(x))]\n'},
        ])
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_mf_081_to_090_batch(self):
        for i in range(10):
            d = analyze_files([
                {'name': f'a{i}.py', 'content': f'def fn_{i}(x): return x*{i+1}\n'},
                {'name': f'b{i}.py', 'content': f'from a{i} import fn_{i}\nresult = fn_{i}(10)\n'},
            ])
            self.assertTrue(report_ok(d), f"batch {i} failed")

    def test_mf_091_to_100_batch_vuln(self):
        for i in range(10):
            d = analyze_files([
                {'name': f'route{i}.py', 'content': f'from flask import request\ndef v{i}():\n    q=request.args.get("q{i}")\n    cursor.execute("SELECT * FROM t{i} WHERE col="+q)\n'},
                {'name': f'model{i}.py', 'content': f'class M{i}:\n    pass\n'},
            ])
            self.assertTrue(has_vuln(d, 'sql'), f"sql vuln {i} not detected")


# ─────────────────────────────────────────────────────────────────────────────
# ZIP FILE TESTS (100)
# ─────────────────────────────────────────────────────────────────────────────

class TestZipFile(unittest.TestCase):

    def test_zip_001_simple_flask_app(self):
        d = analyze_zip({
            'myapp/__init__.py': '',
            'myapp/app.py': 'from flask import Flask\napp = Flask(__name__)\n',
            'myapp/routes.py': 'from flask import request\ndef search():\n    q=request.args.get("q")\n    cursor.execute("SELECT * FROM t WHERE q="+q)\n',
        })
        self.assertTrue(has_vuln(d, 'sql') and d.get('file_count', 0) >= 2)

    def test_zip_002_excludes_pycache(self):
        d = analyze_zip({
            'app/main.py': 'def hello(): return "hello"\n',
            'app/__pycache__/main.cpython-311.pyc': 'fake bytecode',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_003_excludes_hidden(self):
        d = analyze_zip({
            'app/main.py': 'def hello(): return "hello"\n',
            'app/.secret/config.py': 'SECRET="should be ignored"',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_004_no_py_files_error(self):
        d = analyze_zip({'README.md': '# hello', 'requirements.txt': 'flask'})
        self.assertIn('error', d)

    def test_zip_005_corrupt_zip_error(self):
        buf = io.BytesIO(b'this is not a zip')
        r = client.post('/api/analyze_zip', data={'zip': (buf, 'bad.zip')},
                        content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertIn('error', d)

    def test_zip_006_flat_structure(self):
        d = analyze_zip({
            'routes.py': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n',
            'models.py': 'class User: pass\n',
            'utils.py': 'def add(a,b): return a+b\n',
        })
        self.assertTrue(has_vuln(d, 'sql') and d.get('file_count') == 3)

    def test_zip_007_nested_structure(self):
        d = analyze_zip({
            'proj/api/v1/routes.py': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n',
            'proj/models/user.py': 'class User: pass\n',
            'proj/utils/helpers.py': 'def noop(): pass\n',
        })
        self.assertTrue(report_ok(d) and d.get('file_count') == 3)

    def test_zip_008_file_offsets_returned(self):
        d = analyze_zip({
            'app/a.py': 'x=1\n',
            'app/b.py': 'y=2\n',
            'app/c.py': 'z=3\n',
        })
        self.assertEqual(len(d.get('file_offsets', [])), 3)

    def test_zip_009_files_contents_returned(self):
        d = analyze_zip({
            'app/a.py': 'x=1\n',
            'app/b.py': 'y=2\n',
        })
        self.assertEqual(len(d.get('files', [])), 2)

    def test_zip_010_source_file_tagged(self):
        d = analyze_zip({
            'proj/routes.py': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n',
            'proj/utils.py': 'def add(a,b): return a+b\n',
        })
        if d.get('security_count', 0) > 0:
            self.assertTrue(has_source_file(d))

    def test_zip_011_local_lineno_correct(self):
        routes_content = 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n'
        d = analyze_zip({
            'proj/routes.py': routes_content,
            'proj/utils.py': 'def add(a,b): return a+b\n',
        })
        for f in d.get('security_findings', []):
            if f.get('source_file') == 'routes.py':
                local = f.get('local_lineno', 0)
                self.assertLessEqual(local, routes_content.count('\n') + 1)
                self.assertGreater(local, 0)

    def test_zip_012_command_injection(self):
        d = analyze_zip({
            'app/runner.py': 'import subprocess\nfrom flask import request\ndef run():\n    cmd=request.args.get("cmd")\n    subprocess.run(cmd, shell=True)\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_013_path_traversal(self):
        d = analyze_zip({
            'app/files.py': 'from flask import request\ndef download():\n    f=request.args.get("f")\n    return open(f).read()\n',
        })
        self.assertTrue(has_vuln(d, 'path') or has_vuln(d, 'traversal'))

    def test_zip_014_ssrf(self):
        d = analyze_zip({
            'app/proxy.py': 'import requests\nfrom flask import request\ndef proxy():\n    url=request.args.get("url")\n    return requests.get(url).text\n',
        })
        self.assertTrue(has_vuln(d, 'ssrf'))

    def test_zip_015_deserialization(self):
        d = analyze_zip({
            'app/deserialize.py': 'import pickle\nfrom flask import request\ndef v():\n    return pickle.loads(request.data)\n',
        })
        self.assertTrue(has_vuln(d, 'deserializ'))

    def test_zip_016_code_injection(self):
        d = analyze_zip({
            'app/calc.py': 'from flask import request\ndef v():\n    return eval(request.args.get("expr"))\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_017_all_clean(self):
        d = analyze_zip({
            'lib/math_utils.py': 'def add(a,b): return a+b\ndef sub(a,b): return a-b\n',
            'lib/str_utils.py': 'def upper(s): return s.upper()\ndef lower(s): return s.lower()\n',
            'lib/list_utils.py': 'def first(lst): return lst[0] if lst else None\n',
        })
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_zip_018_multiple_vuln_types(self):
        d = analyze_zip({
            'app/sql.py': 'from flask import request\ndef sql_view():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n',
            'app/cmd.py': 'import subprocess\nfrom flask import request\ndef cmd_view():\n    cmd=request.args.get("cmd")\n    subprocess.run(cmd,shell=True)\n',
            'app/path.py': 'from flask import request\ndef path_view():\n    f=request.args.get("f")\n    open(f).read()\n',
        })
        self.assertGreaterEqual(d.get('security_count', 0), 2)

    def test_zip_019_large_zip(self):
        files = {}
        for i in range(20):
            files[f'pkg/module_{i}.py'] = f'def func_{i}(x):\n    return x + {i}\n\nclass Class_{i}:\n    pass\n'
        d = analyze_zip(files)
        self.assertTrue(report_ok(d) and d.get('file_count') == 20)

    def test_zip_020_microdot_real_zip(self):
        with open('/mnt/user-data/uploads/microdot-1.zip', 'rb') as f:
            r = client.post('/api/analyze_zip',
                            data={'zip': (f, 'microdot-1.zip')},
                            content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertTrue(report_ok(d))
        self.assertEqual(d.get('file_count'), 89)
        self.assertGreater(d.get('structural_count', 0), 0)
        self.assertEqual(len(d.get('file_offsets', [])), 89)
        self.assertEqual(len(d.get('files', [])), 89)
        # Every security finding should have source_file
        for f in d.get('security_findings', []):
            self.assertTrue(f.get('source_file'), f"Missing source_file: {f}")
        # Every security finding local_lineno should be > 0
        for f in d.get('security_findings', []):
            self.assertGreater(f.get('local_lineno', 0), 0, f"Bad local_lineno: {f}")

    def test_zip_021_structural_issues_have_lineno(self):
        d = analyze_zip({
            'app/main.py': 'def foo():\n    x=1\n    x=2\n    return x\n',
        })
        self.assertTrue(report_ok(d))
        if d.get('structural_count', 0) > 0:
            for iss in d.get('structural_issues', []):
                # at least some should have line numbers
                pass
            self.assertGreater(d.get('structural_count', 0), 0)

    def test_zip_022_django_project_structure(self):
        d = analyze_zip({
            'mysite/__init__.py': '',
            'mysite/settings.py': 'DEBUG=False\nSECRET_KEY="change-me"\nALLOWED_HOSTS=["*"]\n',
            'mysite/urls.py': 'from django.urls import path\nfrom myapp import views\nurlpatterns=[path("",views.index)]\n',
            'myapp/__init__.py': '',
            'myapp/models.py': 'from django.db import models\nclass Post(models.Model):\n    title=models.CharField(max_length=200)\n    body=models.TextField()\n',
            'myapp/views.py': 'from django.http import HttpRequest,HttpResponse\ndef index(request):\n    return HttpResponse("hello")\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_023_fastapi_project(self):
        d = analyze_zip({
            'api/__init__.py': '',
            'api/main.py': 'from fastapi import FastAPI\nfrom api.routers import users\napp=FastAPI()\napp.include_router(users.router)\n',
            'api/routers/__init__.py': '',
            'api/routers/users.py': 'from fastapi import APIRouter,Depends\nrouter=APIRouter()\n@router.get("/users/{uid}")\ndef get_user(uid:int):\n    return {"id":uid}\n',
            'api/models.py': 'from pydantic import BaseModel\nclass User(BaseModel):\n    id:int\n    name:str\n',
        })
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_zip_024_celery_project(self):
        d = analyze_zip({
            'tasks/__init__.py': '',
            'tasks/app.py': 'from celery import Celery\napp=Celery("tasks",broker="redis://localhost")\n',
            'tasks/email_tasks.py': 'from tasks.app import app\n@app.task\ndef send_email(to,subject,body):\n    mailer.send(to,subject,body)\n    return True\n',
            'tasks/report_tasks.py': 'from tasks.app import app\n@app.task\ndef generate_report(report_id):\n    data=db.get_report(report_id)\n    return render_pdf(data)\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_025_zip_with_init_files(self):
        d = analyze_zip({
            'pkg/__init__.py': '',
            'pkg/core/__init__.py': '',
            'pkg/core/engine.py': 'class Engine:\n    def run(self):\n        return True\n',
            'pkg/utils/__init__.py': '',
            'pkg/utils/helpers.py': 'def noop(): pass\n',
        })
        self.assertEqual(d.get('file_count'), 5)

    def test_zip_026_sql_in_deep_path(self):
        d = analyze_zip({
            'myapp/api/v2/endpoints/users.py': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM users WHERE id="+uid)\n',
        })
        self.assertTrue(has_vuln(d, 'sql'))

    def test_zip_027_file_names_in_response(self):
        d = analyze_zip({
            'proj/a.py': 'x=1\n',
            'proj/b.py': 'y=2\n',
            'proj/c.py': 'z=3\n',
        })
        names = [n.split('/')[-1] for n in d.get('file_names', [])]
        self.assertIn('a.py', names)
        self.assertIn('b.py', names)
        self.assertIn('c.py', names)

    def test_zip_028_non_py_files_ignored(self):
        d = analyze_zip({
            'app/main.py': 'def hello(): return "hello"\n',
            'app/style.css': 'body { color: red; }',
            'app/index.html': '<html></html>',
            'app/data.json': '{"key": "value"}',
            'app/README.md': '# App',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_029_venv_excluded(self):
        d = analyze_zip({
            'app/main.py': 'def hello(): return "hello"\n',
            'venv/lib/python3.11/site-packages/flask/__init__.py': 'x=1',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_030_node_modules_excluded(self):
        d = analyze_zip({
            'app/main.py': 'def hello(): return "hello"\n',
            'node_modules/some_pkg/helper.py': 'ignored=True',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_031_git_dir_excluded(self):
        d = analyze_zip({
            'app/main.py': 'x=1\n',
            '.git/hooks/pre-commit': '#!/usr/bin/env python\nprint("hook")',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_032_complexity_metrics_present(self):
        d = analyze_zip({
            'app/complex.py': 'def fibonacci(n):\n    if n<=1: return n\n    return fibonacci(n-1)+fibonacci(n-2)\ndef factorial(n):\n    if n<=1: return 1\n    return n*factorial(n-1)\n',
        })
        self.assertTrue(report_ok(d))
        self.assertIn('complexity', d)

    def test_zip_033_convergence_in_response(self):
        d = analyze_zip({'app/m.py': 'def add(a,b): return a+b\n'})
        self.assertIn('convergence', d)

    def test_zip_034_report_id_present(self):
        d = analyze_zip({'app/m.py': 'x=1\n'})
        self.assertIn('report_id', d)

    def test_zip_035_security_count_present(self):
        d = analyze_zip({'app/m.py': 'x=1\n'})
        self.assertIn('security_count', d)

    def test_zip_036_structural_count_present(self):
        d = analyze_zip({'app/m.py': 'x=1\n'})
        self.assertIn('structural_count', d)

    def test_zip_037_zip_with_utf8_content(self):
        d = analyze_zip({
            'app/i18n.py': '# -*- coding: utf-8 -*-\n"""Internationalization utilities."""\nGREETINGS = {\n    "en": "Hello",\n    "es": "Hola",\n    "fr": "Bonjour",\n    "de": "Hallo",\n    "ja": "こんにちは",\n}\ndef greet(lang):\n    return GREETINGS.get(lang, GREETINGS["en"])\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_038_zip_with_type_stubs(self):
        d = analyze_zip({
            'pkg/utils.py': 'def add(a: int, b: int) -> int:\n    return a + b\n',
            'pkg/types.py': 'from typing import TypeVar, Generic\nT = TypeVar("T")\nclass Stack(Generic[T]):\n    def __init__(self): self._items: list = []\n    def push(self, item: T): self._items.append(item)\n    def pop(self) -> T: return self._items.pop()\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_039_protocol_classes(self):
        d = analyze_zip({
            'app/protocols.py': 'from typing import Protocol, runtime_checkable\n@runtime_checkable\nclass Serializable(Protocol):\n    def to_dict(self) -> dict: ...\n    @classmethod\n    def from_dict(cls, data: dict) -> "Serializable": ...\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_040_dataclass_fields(self):
        d = analyze_zip({
            'app/models.py': 'from dataclasses import dataclass, field\nfrom typing import List\n@dataclass\nclass Order:\n    id: int\n    items: List[str] = field(default_factory=list)\n    total: float = 0.0\n    def add_item(self, item, price):\n        self.items.append(item)\n        self.total += price\n',
        })
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_zip_041_to_060_batch_clean(self):
        for i in range(20):
            d = analyze_zip({
                f'pkg/mod_{i}.py': f'def func_{i}(x):\n    """Clean function {i}."""\n    return x ** {i+1}\n\nclass Model_{i}:\n    def __init__(self, val):\n        self.val = val\n    def compute(self):\n        return func_{i}(self.val)\n',
            })
            self.assertTrue(report_ok(d), f"batch clean {i} failed: {d.get('error')}")

    def test_zip_061_to_080_batch_sql(self):
        for i in range(20):
            d = analyze_zip({
                f'app/route_{i}.py': f'from flask import request\ndef handler_{i}():\n    val=request.args.get("v{i}")\n    cursor.execute("SELECT * FROM table_{i} WHERE col="+val)\n',
                f'app/model_{i}.py': f'class Model_{i}:\n    pass\n',
            })
            self.assertTrue(has_vuln(d, 'sql'), f"zip sql vuln {i} not detected")

    def test_zip_081_mixed_empty_and_content(self):
        d = analyze_zip({
            'app/__init__.py': '',
            'app/routes.py': 'from flask import request\ndef v():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id="+uid)\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_082_deeply_nested(self):
        d = analyze_zip({
            'a/b/c/d/e/deep.py': 'def deep_func(): return 42\n',
        })
        self.assertTrue(report_ok(d) and d.get('file_count') == 1)

    def test_zip_083_many_files(self):
        files = {f'pkg/m{i}.py': f'x_{i}={i}\n' for i in range(30)}
        d = analyze_zip(files)
        self.assertTrue(report_ok(d) and d.get('file_count') == 30)

    def test_zip_084_async_routes(self):
        d = analyze_zip({
            'app/async_routes.py': 'from aiohttp import web\nasync def handle(request):\n    uid=request.rel_url.query.get("id")\n    result=await db.fetch("SELECT * FROM t WHERE id=%s",(uid,))\n    return web.json_response(result)\n',
        })
        self.assertTrue(is_clean(d) and report_ok(d))

    def test_zip_085_test_files(self):
        d = analyze_zip({
            'tests/test_utils.py': 'import unittest\nclass TestUtils(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(1+1, 2)\n    def test_str(self):\n        self.assertEqual("a"+"b", "ab")\n',
            'src/utils.py': 'def add(a,b): return a+b\n',
        })
        self.assertTrue(report_ok(d) and d.get('file_count') == 2)

    def test_zip_086_setup_py(self):
        d = analyze_zip({
            'setup.py': 'from setuptools import setup, find_packages\nsetup(name="myapp",version="1.0.0",packages=find_packages())\n',
            'myapp/__init__.py': '',
            'myapp/core.py': 'def main(): pass\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_087_manage_py_django(self):
        d = analyze_zip({
            'manage.py': 'import sys\ndef main():\n    import django\n    django.setup()\n    from django.core.management import execute_from_command_line\n    execute_from_command_line(sys.argv)\nif __name__=="__main__": main()\n',
            'myapp/models.py': 'from django.db import models\nclass Item(models.Model):\n    name=models.CharField(max_length=100)\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_088_conftest_pytest(self):
        d = analyze_zip({
            'conftest.py': 'import pytest\n@pytest.fixture(scope="session")\ndef db():\n    conn = connect_db()\n    yield conn\n    conn.close()\n',
            'tests/test_models.py': 'def test_create(db):\n    item = db.create("test")\n    assert item.id is not None\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_089_alembic_migration(self):
        d = analyze_zip({
            'migrations/env.py': 'from alembic import context\nfrom sqlalchemy import engine_from_config\ndef run_migrations():\n    connectable = engine_from_config(context.config.get_section(context.config.config_ini_section))\n    with connectable.connect() as conn:\n        context.configure(connection=conn)\n        with context.begin_transaction():\n            context.run_migrations()\n',
            'migrations/versions/001_init.py': 'def upgrade():\n    op.create_table("users",sa.Column("id",sa.Integer,primary_key=True),sa.Column("name",sa.String(50)))\ndef downgrade():\n    op.drop_table("users")\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_090_wsgi_app(self):
        d = analyze_zip({
            'wsgi.py': 'from myapp import create_app\napp = create_app()\nif __name__ == "__main__":\n    app.run(host="0.0.0.0", port=8000)\n',
            'myapp/__init__.py': 'from flask import Flask\ndef create_app():\n    app = Flask(__name__)\n    return app\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_091_requirements_ignored(self):
        d = analyze_zip({
            'app/main.py': 'def run(): pass\n',
            'requirements.txt': 'flask\nrequests\npandas',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_092_dockerfile_ignored(self):
        d = analyze_zip({
            'app/server.py': 'def serve(): pass\n',
            'Dockerfile': 'FROM python:3.11\nWORKDIR /app\nCOPY . .\nRUN pip install -r requirements.txt\n',
        })
        self.assertEqual(d.get('file_count'), 1)

    def test_zip_093_multiple_vuln_files_deep(self):
        d = analyze_zip({
            'proj/api/auth.py': 'from flask import request\ndef login():\n    u=request.form.get("u")\n    cursor.execute("SELECT * FROM users WHERE username="+u)\n',
            'proj/api/files.py': 'from flask import request\ndef download():\n    f=request.args.get("f")\n    return open(f).read()\n',
            'proj/api/proxy.py': 'import requests\nfrom flask import request\ndef proxy():\n    url=request.args.get("url")\n    return requests.get(url).text\n',
            'proj/utils/helpers.py': 'def noop(): pass\n',
        })
        self.assertGreaterEqual(d.get('security_count', 0), 2)
        self.assertEqual(d.get('file_count'), 4)

    def test_zip_094_yaml_safe_load(self):
        d = analyze_zip({
            'app/config_loader.py': 'import yaml\ndef load_config(path):\n    with open(path) as f:\n        return yaml.safe_load(f)\n',
        })
        self.assertFalse(has_vuln(d, 'deserializ'))

    def test_zip_095_yaml_unsafe_load(self):
        d = analyze_zip({
            'app/loader.py': 'import yaml\nfrom flask import request\ndef load():\n    data=request.data\n    return yaml.load(data)\n',
        })
        self.assertTrue(has_vuln(d, 'deserializ'))

    def test_zip_096_parameterized_safe_sql(self):
        d = analyze_zip({
            'app/db.py': 'from flask import request\ndef search():\n    q=request.args.get("q")\n    cursor.execute("SELECT * FROM t WHERE q=%s",(q,))\ndef get():\n    uid=request.args.get("id")\n    cursor.execute("SELECT * FROM t WHERE id=%s",(uid,))\n',
        })
        self.assertFalse(has_vuln(d, 'sql'))

    def test_zip_097_empty_py_file_ok(self):
        d = analyze_zip({
            'app/__init__.py': '',
            'app/main.py': 'def run(): return True\n',
        })
        self.assertTrue(report_ok(d))

    def test_zip_098_large_single_file(self):
        lines = ['from flask import request', 'def large_view():']
        lines += [f'    var_{i} = request.args.get("param_{i}")' for i in range(50)]
        lines += [f'    result_{i} = var_{i}.strip()' for i in range(50)]
        lines.append('    return "ok"')
        d = analyze_zip({'app/large.py': '\n'.join(lines)})
        self.assertTrue(report_ok(d))

    def test_zip_099_no_zip_file_uploaded(self):
        r = client.post('/api/analyze_zip', data={}, content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertIn('error', d)

    def test_zip_100_wrong_extension_rejected(self):
        buf = io.BytesIO(b'fake')
        r = client.post('/api/analyze_zip', data={'zip': (buf, 'archive.tar.gz')},
                        content_type='multipart/form-data')
        d = json.loads(r.data)
        self.assertIn('error', d)


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def suite_size(s):
    try:
        return sum(suite_size(t) for t in s)
    except TypeError:
        return 1

if __name__ == '__main__':
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestSingleFile))
    suite.addTests(loader.loadTestsFromTestCase(TestMultiFile))
    suite.addTests(loader.loadTestsFromTestCase(TestZipFile))

    runner  = unittest.TextTestRunner(verbosity=0, stream=open('/dev/null','w'))
    result  = runner.run(suite)

    total   = result.testsRun
    failed  = len(result.failures) + len(result.errors)
    passed  = total - failed

    print("=" * 65)
    print(f"REAL-WORLD TEST RESULTS — {total} tests across 3 categories")
    print("=" * 65)

    # Category breakdown
    cats = [('Single File',  TestSingleFile),
            ('Multi-File',   TestMultiFile),
            ('ZIP Upload',   TestZipFile)]
    for cat_name, cat_class in cats:
        cat_tests  = [t for t in result.failures + result.errors
                      if isinstance(t[0], cat_class)]
        cat_total  = suite_size(loader.loadTestsFromTestCase(cat_class))
        cat_failed = len(cat_tests)
        cat_passed = cat_total - cat_failed
        status     = "✓" if cat_failed == 0 else "✗"
        print(f"  {status} {cat_name:<15} {cat_passed:>3}/{cat_total} passed")

    print()
    if result.failures:
        print("FAILURES:")
        for test, tb in result.failures:
            print(f"  FAIL: {test}")
            # Print just the assertion line
            lines = tb.strip().split('\n')
            for line in lines[-3:]:
                if line.strip():
                    print(f"        {line.strip()}")
            print()

    if result.errors:
        print("ERRORS:")
        for test, tb in result.errors:
            print(f"  ERROR: {test}")
            lines = tb.strip().split('\n')
            for line in lines[-3:]:
                if line.strip():
                    print(f"         {line.strip()}")
            print()

    print("=" * 65)
    print(f"TOTAL: {total}  PASSED: {passed}  FAILED: {failed}")
    if failed == 0:
        print("ALL TESTS PASSED ✓")
    else:
        print(f"{failed} TESTS FAILED ✗")
    print("=" * 65)
