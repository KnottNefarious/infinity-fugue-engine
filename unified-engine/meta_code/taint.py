"""
taint.py — Path-Sensitive Taint Analysis

Implements Move 2 (Dissonance) at the security level:
    Γ ⊢ φ  where  φ = "input at sink S is safe"
    If Γ cannot prove φ → security dissonance → Finding

Architecture: CFG × TaintState product construction.

Key fixes from the Replit version:
  Fix #1: ALL function bodies analyzed (not just called ones)
  Fix #2: BinOp returns taint from EITHER operand (not just truthy side)
  Fix #3: All 8 sink types implemented with actual detection code
  Fix #4: Sinks checked inside ALL expression contexts (Return, Assign, Expr)
  Fix #5: abort() recognized as path terminator for correct guard propagation
"""

import ast
from typing import Dict, List, Optional, Set, Tuple
from meta_code.core import Finding
from meta_code.sinks import (
    AUTH_GUARDS, SANITIZERS, PARAMETERIZED_SQL_INDICATORS,
    AUTH_SENSITIVE_PATTERNS, IDOR, MISSING_AUTH, XSS, SQL_INJECTION, SSRF
)


# ── Tainted Value ─────────────────────────────────────────────────────────────

class TaintedValue:
    def __init__(self, tainted: bool = False, path: Optional[List[str]] = None,
                 source: str = 'request'):
        self.tainted = tainted
        self.path = list(path) if path else [source]
        self.source = source

    def add_step(self, label: str) -> 'TaintedValue':
        return TaintedValue(self.tainted, self.path + [label], self.source)

    def merge(self, other: 'TaintedValue') -> 'TaintedValue':
        merged_tainted = self.tainted or other.tainted
        if self.tainted and not other.tainted:
            path = self.path
        elif other.tainted and not self.tainted:
            path = other.path
        else:
            path = list(dict.fromkeys(self.path + other.path))
        return TaintedValue(merged_tainted, path, self.source)

    def __bool__(self):
        return self.tainted

    def __repr__(self):
        return f"TaintedValue(tainted={self.tainted}, path={self.path})"


# ── Taint State ───────────────────────────────────────────────────────────────

class TaintState:
    def __init__(self):
        self._vars: Dict[str, Optional[TaintedValue]] = {}
        self._guards_seen: Set[str] = set()

    def get(self, name: str) -> Optional[TaintedValue]:
        return self._vars.get(name)

    def set(self, name: str, value: Optional[TaintedValue]):
        self._vars[name] = value

    def add_guard(self, guard: str):
        self._guards_seen.add(guard)

    def has_guard(self) -> bool:
        return bool(self._guards_seen)

    def copy(self) -> 'TaintState':
        new = TaintState()
        new._vars = dict(self._vars)
        new._guards_seen = set(self._guards_seen)
        return new

    def merge_with(self, other: 'TaintState') -> 'TaintState':
        merged = TaintState()
        for name in set(self._vars) | set(other._vars):
            v1, v2 = self.get(name), other.get(name)
            if v1 is None and v2 is None:
                merged.set(name, None)
            elif v1 is None:
                merged.set(name, v2)
            elif v2 is None:
                merged.set(name, v1)
            else:
                merged.set(name, v1.merge(v2))
        merged._guards_seen = self._guards_seen & other._guards_seen
        return merged


# ── Path-Sensitive Taint Analyzer ─────────────────────────────────────────────

class PathSensitiveTaintAnalyzer:

    def __init__(self):
        self.findings: List[Finding] = []
        self._fingerprints: Set[Tuple] = set()
        self._functions: Dict[str, ast.FunctionDef] = {}
        self._call_depth: int = 0
        self._max_call_depth: int = 5

    def analyze(self, tree: ast.AST) -> List[Finding]:
        self._collect_functions(tree)
        for func in self._functions.values():
            self._analyze_body(func.body, TaintState())
        # Module-level code
        module_stmts = [s for s in ast.iter_child_nodes(tree)
                        if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef,
                                              ast.ClassDef, ast.Import, ast.ImportFrom))]
        if module_stmts:
            self._analyze_body(module_stmts, TaintState())
        return self.findings

    def _collect_functions(self, node: ast.AST):
        """Collect ALL function defs including decorated Flask routes."""
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._functions[child.name] = child
            elif isinstance(child, ast.ClassDef):
                for item in child.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._functions[f"{child.name}.{item.name}"] = item

    # ── Statement Analysis ────────────────────────────────────────────────────

    def _analyze_body(self, stmts: list, state: TaintState, live: bool = True):
        for stmt in stmts:
            if not live:
                break
            if isinstance(stmt, ast.Assign):
                val = self._eval(stmt.value, state)
                self._scan_expr_for_sinks(stmt.value, state, stmt)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        state.set(target.id, val)
                    elif isinstance(target, ast.Subscript):
                        if isinstance(target.value, ast.Name) and val and val.tainted:
                            existing = state.get(target.value.id)
                            state.set(target.value.id,
                                     existing.merge(val) if existing else val)
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                state.set(elt.id, val)

            elif isinstance(stmt, ast.AugAssign):
                existing = state.get(stmt.target.id) if isinstance(stmt.target, ast.Name) else None
                rhs = self._eval(stmt.value, state)
                result = existing.merge(rhs) if (existing and existing.tainted and rhs and rhs.tainted) \
                    else (existing if (existing and existing.tainted) else rhs)
                if isinstance(stmt.target, ast.Name) and result:
                    state.set(stmt.target.id, result.add_step(stmt.target.id))

            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value and isinstance(stmt.target, ast.Name):
                    state.set(stmt.target.id, self._eval(stmt.value, state))

            elif isinstance(stmt, ast.Return):
                if stmt.value:
                    self._scan_expr_for_sinks(stmt.value, state, stmt)
                    val = self._eval(stmt.value, state)
                    if val and val.tainted and self._involves_html(stmt.value, state):
                        self._add_finding(XSS, val, 'HTTP response (return)', stmt)
                live = False

            elif isinstance(stmt, ast.Expr):
                # Scan entire expression for sinks at any nesting depth
                # This handles: open(x).write(y), requests.get(x).json(), etc.
                self._scan_expr_for_sinks(stmt.value, state, stmt)
                if isinstance(stmt.value, ast.Call):
                    self._eval_call(stmt.value, state)
                if self._is_terminator_call(stmt):
                    live = False

            elif isinstance(stmt, ast.If):
                live = self._handle_if(stmt, state, live)

            elif isinstance(stmt, (ast.For, ast.While)):
                if hasattr(stmt, 'target') and isinstance(stmt.target, ast.Name):
                    it = self._eval(stmt.iter, state) if hasattr(stmt, 'iter') else None
                    if it and it.tainted:
                        state.set(stmt.target.id, it.add_step(stmt.target.id))
                self._analyze_body(stmt.body, state)
                if stmt.orelse:
                    self._analyze_body(stmt.orelse, state)

            elif isinstance(stmt, ast.Try):
                self._analyze_body(stmt.body, state)
                for h in stmt.handlers:
                    self._analyze_body(h.body, state)
                if stmt.orelse:
                    self._analyze_body(stmt.orelse, state)
                if hasattr(stmt, 'finalbody') and stmt.finalbody:
                    self._analyze_body(stmt.finalbody, state)

            elif isinstance(stmt, ast.Raise):
                live = False

    def _is_terminator_call(self, stmt: ast.Expr) -> bool:
        if not isinstance(stmt.value, ast.Call):
            return False
        func = stmt.value.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else None)
        return name in {'abort', 'exit', 'quit'}

    def _scan_expr_for_sinks(self, node: ast.AST, state: TaintState, stmt: ast.AST):
        """Recursively scan expression for sink calls at any nesting depth."""
        if node is None:
            return
        if isinstance(node, ast.Call):
            self._check_call_sink(node, state, stmt)
            if isinstance(node.func, ast.Attribute):
                self._scan_expr_for_sinks(node.func.value, state, stmt)
            for arg in node.args:
                self._scan_expr_for_sinks(arg, state, stmt)
            for kw in node.keywords:
                if kw.value:
                    self._scan_expr_for_sinks(kw.value, state, stmt)
        elif isinstance(node, ast.Attribute):
            self._scan_expr_for_sinks(node.value, state, stmt)
        elif isinstance(node, ast.BinOp):
            self._scan_expr_for_sinks(node.left, state, stmt)
            self._scan_expr_for_sinks(node.right, state, stmt)
        elif isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    self._scan_expr_for_sinks(v.value, state, stmt)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                self._scan_expr_for_sinks(elt, state, stmt)

    # ── Control Flow ──────────────────────────────────────────────────────────

    def _handle_if(self, stmt: ast.If, state: TaintState, live: bool) -> bool:
        """
        Path-splitting with correct guard propagation.

        Critical case: if not auth(): abort() → then terminates
            Post-if code is only reachable when auth() was True.
            The auth check IS a guard for the post-if code.
        """
        # Dead code: if False:
        if isinstance(stmt.test, ast.Constant) and not stmt.test.value:
            if stmt.orelse:
                return self._analyze_body_ret(stmt.orelse, state, live)
            return live

        then_state = state.copy()
        else_state = state.copy()

        then_live = self._analyze_body_ret(stmt.body, then_state, live)
        else_live = True
        if stmt.orelse:
            else_live = self._analyze_body_ret(stmt.orelse, else_state, live)

        if not then_live and not else_live:
            return False
        elif not then_live:
            # Then terminated (abort/return/raise).
            # Post-if = condition was False path.
            # If condition was "if not auth()" → post-if means auth() was True → guarded.
            for name, val in else_state._vars.items():
                state.set(name, val)
            state._guards_seen = else_state._guards_seen.copy()
            # Extract guard from the negated condition
            guard = self._extract_guard_from_negated(stmt.test)
            if guard:
                state.add_guard(guard)
        elif not else_live:
            for name, val in then_state._vars.items():
                state.set(name, val)
            state._guards_seen = then_state._guards_seen.copy()
        else:
            merged = then_state.merge_with(else_state)
            for name, val in merged._vars.items():
                state.set(name, val)
            state._guards_seen = then_state._guards_seen & else_state._guards_seen

        return then_live or else_live

    def _analyze_body_ret(self, stmts: list, state: TaintState, live: bool) -> bool:
        """Analyze body, return whether path is still live."""
        for stmt in stmts:
            if not live:
                break
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                live = False
            elif isinstance(stmt, ast.Expr) and self._is_terminator_call(stmt):
                self._analyze_body([stmt], state, live)
                live = False
            elif isinstance(stmt, ast.If):
                live = self._handle_if(stmt, state, live)
            else:
                self._analyze_body([stmt], state, live)
        return live

    def _extract_guard_from_negated(self, test: ast.AST) -> Optional[str]:
        """
        Extract guard name from a condition that, when False, means the code is guarded.
        'if not auth(): abort()' → condition False = auth() was True → guard = 'auth'
        'if not current_user.can_access(): abort()' → guard = 'can_access'
        """
        # if not X: abort() → guard is X
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._extract_guard_name(test.operand)
        # if X: abort() → being here means NOT X, which is not necessarily guarded
        # (this pattern is usually wrong auth logic)
        return None

    def _extract_guard_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call):
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else None)
            if name and name in AUTH_GUARDS:
                return name
        if isinstance(node, ast.Attribute):
            if node.attr in AUTH_GUARDS:
                return node.attr
            if isinstance(node.value, ast.Name) and node.value.id == 'current_user':
                return f'current_user.{node.attr}'
        return None

    def _extract_guard_from_expr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self._extract_guard_name(node.operand)
        return self._extract_guard_name(node)

    # ── Expression Evaluation ─────────────────────────────────────────────────

    def _eval(self, node: ast.AST, state: TaintState) -> Optional[TaintedValue]:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node, state)
        if isinstance(node, ast.Call):
            return self._eval_call(node, state)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node, state)
        if isinstance(node, ast.JoinedStr):
            return self._eval_fstring(node, state)
        if isinstance(node, ast.Subscript):
            container = self._eval(node.value, state)
            if container and container.tainted:
                key = ''
                if isinstance(node.slice, ast.Constant):
                    key = str(node.slice.value)
                elif isinstance(node.slice, ast.Name):
                    key = node.slice.id
                return container.add_step(f'[{key}]') if key else container
            return None
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for elt in node.elts:
                val = self._eval(elt, state)
                if val and val.tainted:
                    return val
            return None
        if isinstance(node, ast.Dict):
            for v in node.values:
                val = self._eval(v, state)
                if val and val.tainted:
                    return val
            return None
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, state)
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                val = self._eval(v, state)
                if val and val.tainted:
                    return val
            return None
        if isinstance(node, ast.IfExp):
            for n in (node.body, node.orelse):
                val = self._eval(n, state)
                if val and val.tainted:
                    return val
            return None
        return None

    def _eval_attribute(self, node: ast.Attribute, state: TaintState) -> Optional[TaintedValue]:
        # request.args, request.form, request.data, request.json, etc.
        if isinstance(node.value, ast.Name) and node.value.id == 'request':
            if node.attr in {'args', 'form', 'json', 'values', 'headers',
                             'cookies', 'data', 'files', 'environ', 'stream'}:
                return TaintedValue(True, ['request', node.attr], 'request')

        # Chained attribute: request.args.get → parent=request.args (tainted), attr=get
        if isinstance(node.value, ast.Attribute):
            parent = self._eval_attribute(node.value, state)
            if parent and parent.tainted:
                return parent.add_step(node.attr)

        base = self._eval(node.value, state)
        if base and base.tainted:
            return base.add_step(node.attr)
        return None

    def _eval_call(self, node: ast.Call, state: TaintState) -> Optional[TaintedValue]:
        func = node.func
        call_name = (func.id if isinstance(func, ast.Name)
                     else func.attr if isinstance(func, ast.Attribute) else None)

        # Sanitizer
        if call_name in SANITIZERS:
            return None

        # request.args.get('id'), request.form.get('key'), etc.
        if isinstance(func, ast.Attribute) and call_name == 'get':
            if isinstance(func.value, ast.Attribute):
                parent = self._eval_attribute(func.value, state)
                if parent and parent.tainted:
                    return parent.add_step('get')
            elif isinstance(func.value, ast.Name) and func.value.id == 'request':
                return TaintedValue(True, ['request', 'get'], 'request')

        # request.get_json(), request.get_data()
        if isinstance(func, ast.Attribute) and call_name in {'get_json', 'get_data'}:
            if isinstance(func.value, ast.Name) and func.value.id == 'request':
                return TaintedValue(True, ['request', call_name], 'request')

        # Attribute call: propagate from base if tainted
        if isinstance(func, ast.Attribute):
            base = self._eval(func.value, state)
            if base and base.tainted:
                if call_name in SANITIZERS:
                    return None
                return base.add_step(call_name)

        # Inter-procedural
        if call_name and call_name in self._functions and self._call_depth < self._max_call_depth:
            return self._analyze_call_interprocedural(self._functions[call_name], node.args, state)

        # Propagate from any tainted argument
        for arg in node.args:
            val = self._eval(arg, state)
            if val and val.tainted:
                return val.add_step(call_name or 'call')
        for kw in node.keywords:
            if kw.value:
                val = self._eval(kw.value, state)
                if val and val.tainted:
                    return val.add_step(call_name or 'call')
        return None

    def _analyze_call_interprocedural(self, func: ast.FunctionDef,
                                      call_args: list,
                                      caller_state: TaintState) -> Optional[TaintedValue]:
        self._call_depth += 1
        try:
            child_state = TaintState()
            for i, param in enumerate(func.args.args):
                if param.arg == 'self':
                    continue
                if i < len(call_args):
                    child_state.set(param.arg, self._eval(call_args[i], caller_state))
            self._analyze_body(func.body, child_state)
            return self._find_return_taint(func.body, child_state)
        finally:
            self._call_depth -= 1

    def _find_return_taint(self, stmts: list, state: TaintState) -> Optional[TaintedValue]:
        for stmt in stmts:
            if isinstance(stmt, ast.Return) and stmt.value:
                return self._eval(stmt.value, state)
            if isinstance(stmt, ast.If):
                for branch in [stmt.body, stmt.orelse]:
                    val = self._find_return_taint(branch, state)
                    if val and val.tainted:
                        return val
        return None

    def _eval_binop(self, node: ast.BinOp, state: TaintState) -> Optional[TaintedValue]:
        """FIX #2: return taint from EITHER operand, not just the truthy one."""
        left = self._eval(node.left, state)
        right = self._eval(node.right, state)
        if left and left.tainted and right and right.tainted:
            return left.merge(right)
        if left and left.tainted:
            return left
        if right and right.tainted:
            return right
        return None

    def _eval_fstring(self, node: ast.JoinedStr, state: TaintState) -> Optional[TaintedValue]:
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                val = self._eval(value.value, state)
                if val and val.tainted:
                    return val.add_step('fstring')
        return None

    # ── Sink Checking ─────────────────────────────────────────────────────────

    def _check_call_sink(self, node: ast.Call, state: TaintState, stmt: ast.AST):
        func = node.func

        if isinstance(func, ast.Attribute):
            attr = func.attr
            module = self._get_module_name(func.value)

            # SQL Injection: cursor.execute / executemany
            if attr in {'execute', 'executemany'} and node.args:
                qval = self._eval(node.args[0], state)
                if qval and qval.tainted and not self._is_parameterized_query(node.args[0]):
                    self._add_finding(SQL_INJECTION, qval, f'cursor.{attr}(query)', stmt)

            # os.system(cmd) — always dangerous, no shell=True needed
            if attr == 'system' and module == 'os' and node.args:
                cval = self._eval(node.args[0], state)
                if cval and cval.tainted:
                    from meta_code.sinks import OS_COMMAND
                    self._add_finding(OS_COMMAND, cval, 'os.system(cmd)', stmt)

            # subprocess.run/call/Popen with shell=True
            if attr in {'run', 'call', 'Popen', 'check_output', 'check_call'}:
                if self._has_shell_true(node) and node.args:
                    cval = self._eval(node.args[0], state)
                    if cval and cval.tainted:
                        from meta_code.sinks import COMMAND_INJECTION
                        self._add_finding(COMMAND_INJECTION, cval,
                                         f'subprocess.{attr}(cmd, shell=True)', stmt)

            # Deserialization
            if attr in {'loads', 'load'} and node.args:
                dval = self._eval(node.args[0], state)
                if dval and dval.tainted:
                    if module in {'pickle', 'marshal', 'shelve'} or \
                       (module == 'yaml' and attr == 'load'):
                        from meta_code.sinks import UNSAFE_DESERIALIZATION
                        self._add_finding(UNSAFE_DESERIALIZATION, dval,
                                         f'{module}.{attr}(data)', stmt)

            # SSRF: requests.get/post/etc, urllib.request.urlopen
            if attr in {'get', 'post', 'put', 'delete', 'patch', 'request'}:
                if module in {'requests', 'httpx', 'aiohttp', 'urllib',
                              'session', 'Session', 'client'}:
                    url_val = None
                    if node.args:
                        url_val = self._eval(node.args[0], state)
                    else:
                        for kw in node.keywords:
                            if kw.arg == 'url':
                                url_val = self._eval(kw.value, state)
                    if url_val and url_val.tainted:
                        self._add_finding(SSRF, url_val,
                                         f'{module}.{attr}(url)', stmt)

            # urllib.request.urlopen(url) — SSRF via attribute chain
            if attr == 'urlopen' and node.args:
                url_val = self._eval(node.args[0], state)
                if url_val and url_val.tainted:
                    self._add_finding(SSRF, url_val, 'urlopen(url)', stmt)

            # Auth-sensitive operations (IDOR / Missing Auth)
            # Check ALL args — first arg may be clean (e.g. current_user.account),
            # but second arg (to, doc_id, etc.) can be tainted
            if attr in AUTH_SENSITIVE_PATTERNS and not state.has_guard():
                tainted_arg = None
                for arg in node.args:
                    val = self._eval(arg, state)
                    if val and val.tainted:
                        tainted_arg = val
                        break
                if tainted_arg:
                    mutations = {'delete', 'update', 'transfer', 'send', 'publish',
                                 'drop', 'remove', 'set_password', 'delete_user',
                                 'delete_record', 'delete_object'}
                    sink_def = MISSING_AUTH if attr in mutations else IDOR
                    self._add_finding(sink_def, tainted_arg, f'{attr}(id)', stmt)

            # abort() guard
            if attr == 'abort':
                state.add_guard('abort')

        elif isinstance(func, ast.Name):
            name = func.id

            if name == 'abort':
                state.add_guard('abort')
                return

            # open() — Path Traversal
            if name == 'open' and node.args:
                pval = self._eval(node.args[0], state)
                if pval and pval.tainted:
                    from meta_code.sinks import PATH_TRAVERSAL
                    self._add_finding(PATH_TRAVERSAL, pval, 'open(path)', stmt)

            # os.system() — Command Injection
            if name == 'system' and node.args:
                cval = self._eval(node.args[0], state)
                if cval and cval.tainted:
                    from meta_code.sinks import OS_COMMAND
                    self._add_finding(OS_COMMAND, cval, 'os.system(cmd)', stmt)

            # urlopen()
            if name == 'urlopen' and node.args:
                uval = self._eval(node.args[0], state)
                if uval and uval.tainted:
                    self._add_finding(SSRF, uval, 'urlopen(url)', stmt)

            # render_template_string()
            if name == 'render_template_string' and node.args:
                tval = self._eval(node.args[0], state)
                if tval and tval.tainted:
                    self._add_finding(XSS, tval,
                                     'render_template_string(template)', stmt)

            # subprocess.run/call/Popen at name level
            if name in {'run', 'call', 'Popen', 'check_output', 'check_call'}:
                if self._has_shell_true(node) and node.args:
                    cval = self._eval(node.args[0], state)
                    if cval and cval.tainted:
                        from meta_code.sinks import COMMAND_INJECTION
                        self._add_finding(COMMAND_INJECTION, cval,
                                         f'{name}(cmd, shell=True)', stmt)

            # pickle.loads / yaml.load at name level
            if name in {'loads', 'load'} and node.args:
                dval = self._eval(node.args[0], state)
                if dval and dval.tainted:
                    from meta_code.sinks import UNSAFE_DESERIALIZATION
                    self._add_finding(UNSAFE_DESERIALIZATION, dval,
                                     f'{name}(data)', stmt)

    def _involves_html(self, node: ast.AST, state: TaintState) -> bool:
        HTML_TAGS = {'<html', '<div', '<script', '<h1', '<h2', '<h3', '<body',
                     '<span', '<p>', '<form', '<input', '<table', '<head',
                     '<title', '<meta', '<link', '<style'}
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return any(tag in node.value.lower() for tag in HTML_TAGS)
        if isinstance(node, ast.BinOp):
            return self._involves_html(node.left, state) or self._involves_html(node.right, state)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant) and self._involves_html(v, state):
                    return True
        return False

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _is_parameterized(self, call_node: ast.Call) -> bool:
        return False  # Deprecated - use _is_parameterized_query

    def _is_parameterized_query(self, arg0: ast.AST) -> bool:
        """
        A SQL query is parameterized if:
        1. The first argument is a literal string containing %s, ?, or :name
        2. The first argument is NOT a concatenation (BinOp)
        
        cursor.execute("SELECT %s", (val,)) -> parameterized (arg0 is literal with %s)
        cursor.execute("SELECT " + val) -> NOT parameterized (BinOp)
        cursor.executemany("INSERT (" + uid + ")", []) -> NOT parameterized (BinOp)
        """
        if arg0 is None:
            return False
        # If arg0 is a BinOp (string concat), it's NOT parameterized
        if isinstance(arg0, ast.BinOp):
            return False
        # If it's a literal string with a placeholder marker, it's parameterized
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
            return any(m in arg0.value for m in PARAMETERIZED_SQL_INDICATORS)
        # f-strings, variables - treat as potentially not parameterized
        # (we'll flag these and let the user verify)
        return False

    def _has_shell_true(self, call_node: ast.Call) -> bool:
        for kw in call_node.keywords:
            if kw.arg == 'shell':
                v = kw.value
                if isinstance(v, ast.Constant) and v.value is True:
                    return True
                if isinstance(v, ast.NameConstant) and v.value is True:
                    return True
        return False

    def _get_module_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ''

    def _add_finding(self, sink, tainted_val: TaintedValue,
                    sink_desc: str, stmt: ast.AST):
        lineno = getattr(stmt, 'lineno', None)
        fingerprint = (sink.vuln_type, lineno, sink_desc)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)
        self.findings.append(Finding(
            vuln_type=sink.vuln_type,
            severity=sink.severity,
            path=list(tainted_val.path),
            sink=sink_desc,
            reason=sink.reason,
            fix=sink.fix,
            lineno=lineno,
            exploitability=sink.exploitability,
            exploit_reason=sink.exploit_reason,
        ))
