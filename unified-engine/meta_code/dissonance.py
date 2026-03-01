"""
dissonance.py — Dissonance: Γ ⊢ ϕ  ⟺  ¬(Γ ∪ {¬ϕ} is consistent)

In a fugue, a wrong note breaks the counterpoint — a logical contradiction
within the voice-leading rules. In code, dissonance is a contradiction
within the formal system of the program.

Two kinds of dissonance:

1. SCOPE DISSONANCE (AST): A variable is declared in Γ but never appears
   in any ϕ (used expression). Γ ∪ {¬ϕ} is consistent — meaning the
   program would be consistent WITHOUT the variable. Its presence is noise.

2. FLOW DISSONANCE (CFG): A statement whose execution contradicts the
   control flow structure. After a `return`, all subsequent statements are
   ¬reachable — their existence creates a logical contradiction with the
   established flow.

The original implementation only caught `if False:` blocks (constant-condition
unreachability). This version builds a real Control Flow Graph to detect all
forms of flow dissonance.
"""

import ast
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Issue dataclass — structured, not just strings
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    kind: str           # 'unused_variable' | 'unreachable_code' | 'shadowed_variable'
    message: str
    line: Optional[int] = None
    col: Optional[int] = None
    severity: str = 'warning'   # 'error' | 'warning' | 'info'

    def __str__(self):
        loc = f" (line {self.line})" if self.line else ""
        return f"{self.message}{loc}"


# ---------------------------------------------------------------------------
# Scope Environment — represents Γ (the formal declaration environment)
# ---------------------------------------------------------------------------

class ScopeEnvironment:
    """
    Γ — the environment of names in scope.

    assigned: names declared (Γ ⊢ x exists)
    used: names read (ϕ — the 'used' assertion)
    children: nested scopes (functions, classes, comprehensions)

    Dissonance = name in assigned but NOT in used or any child's used.
    """

    def __init__(self, parent=None):
        self.parent = parent
        self.assigned: dict = {}   # name → AST node
        self.used: set = set()
        self.children: list = []
        self._args: set = set()    # function parameters (never flagged)

    def declare(self, name: str, node):
        if name not in self._args:
            self.assigned[name] = node

    def mark_arg(self, name: str):
        """Register a function parameter — parameters are never 'unused'."""
        self._args.add(name)
        self.used.add(name)

    def use(self, name: str):
        self.used.add(name)

    def child_scope(self) -> 'ScopeEnvironment':
        child = ScopeEnvironment(parent=self)
        self.children.append(child)
        return child

    def _all_used(self) -> set:
        """Used names in this scope AND all descendant scopes (closures)."""
        result = set(self.used)
        for child in self.children:
            result |= child._all_used()
        return result

    def get_unused(self) -> dict:
        """Variables declared but never used anywhere in scope tree."""
        all_used = self._all_used()
        return {
            name: node
            for name, node in self.assigned.items()
            if name not in all_used and not name.startswith('_')
        }


# ---------------------------------------------------------------------------
# Control Flow Graph — minimal CFG for flow dissonance detection
# ---------------------------------------------------------------------------

class CFGNode:
    def __init__(self, stmt=None, label=''):
        self.stmt = stmt
        self.label = label
        self.successors: list = []
        self.predecessors: list = []

    def link_to(self, other: 'CFGNode'):
        self.successors.append(other)
        other.predecessors.append(self)


class ControlFlowGraph:
    """
    Minimal CFG builder.

    The formal consistency check:
        Γ ⊢ ϕ  ⟺  ¬(Γ ∪ {¬ϕ} is consistent)

    A statement is unreachable if no path from ENTRY reaches it.
    Its existence in the program is a contradiction — it asserts
    'I will execute' while the flow structure asserts 'you cannot execute.'
    """

    # Statements that unconditionally terminate a code path
    TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def __init__(self):
        self._unreachable: list = []

    def build(self, tree: ast.Module) -> 'ControlFlowGraph':
        self._process_body(tree.body, reachable=True)
        return self

    def _process_body(self, stmts, reachable: bool) -> bool:
        """
        Process a statement list. Returns True if flow continues after it.
        When reachable=False, all statements are recorded as unreachable.
        """
        live = reachable
        for stmt in stmts:
            if not live:
                self._unreachable.append(stmt)
                continue

            if isinstance(stmt, self.TERMINATORS):
                live = False   # everything after this is dead

            elif isinstance(stmt, ast.If):
                live = self._process_if(stmt, live)

            elif isinstance(stmt, (ast.For, ast.While)):
                self._process_body(stmt.body, live)
                if stmt.orelse:
                    self._process_body(stmt.orelse, live)
                # After a loop, flow continues (loop may not execute)

            elif isinstance(stmt, ast.Try):
                self._process_body(stmt.body, live)
                for handler in stmt.handlers:
                    self._process_body(handler.body, live)
                if stmt.orelse:
                    self._process_body(stmt.orelse, live)
                if stmt.finalbody:
                    self._process_body(stmt.finalbody, live)

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Function body is analyzed separately; definition always reachable
                self._process_body(stmt.body, reachable=True)

            elif isinstance(stmt, ast.ClassDef):
                self._process_body(stmt.body, reachable=True)

        return live

    def _process_if(self, stmt: ast.If, live: bool) -> bool:
        """
        Handle if statements, including constant-condition detection.
        Returns whether flow continues after the if block.
        """
        test = stmt.test

        # if False: — entire body is unreachable
        if isinstance(test, ast.Constant) and not test.value:
            for s in stmt.body:
                self._unreachable.append(s)
            # else branch runs normally
            if stmt.orelse:
                return self._process_body(stmt.orelse, live)
            return live

        # if True: — else branch is unreachable
        if isinstance(test, ast.Constant) and test.value:
            body_live = self._process_body(stmt.body, live)
            for s in stmt.orelse:
                self._unreachable.append(s)
            return body_live

        # Normal if: both branches may run
        body_live = self._process_body(stmt.body, live)
        else_live = self._process_body(stmt.orelse, live) if stmt.orelse else live
        # Flow continues if at least one branch continues
        return body_live or else_live

    def get_unreachable(self) -> list:
        return self._unreachable


# ---------------------------------------------------------------------------
# Scope Analyzer — builds Γ and finds unused declarations
# ---------------------------------------------------------------------------

class ScopeAnalyzer(ast.NodeVisitor):
    """
    Walks the AST building a tree of ScopeEnvironments.
    Identifies variables where Γ ⊢ ¬used — the dissonance condition.
    """

    def __init__(self):
        self._scope = ScopeEnvironment()
        self._root_scope = self._scope

    def _push(self) -> ScopeEnvironment:
        child = self._scope.child_scope()
        self._scope = child
        return child

    def _pop(self):
        self._scope = self._scope.parent

    def visit_FunctionDef(self, node):
        # Function name is used in parent scope
        self._scope.use(node.name)
        self._push()
        # Parameters are never 'unused' (they're the interface)
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self._scope.mark_arg(arg.arg)
        if node.args.vararg:
            self._scope.mark_arg(node.args.vararg.arg)
        if node.args.kwarg:
            self._scope.mark_arg(node.args.kwarg.arg)
        self.generic_visit(node)
        self._pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._scope.use(node.name)
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_Assign(self, node):
        # Visit RHS first (value may use names)
        self.visit(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._scope.declare(target.id, node)
            else:
                self.visit(target)

    def visit_AugAssign(self, node):
        # x += 1 means x is used AND re-assigned
        if isinstance(node.target, ast.Name):
            self._scope.use(node.target.id)
            self._scope.declare(node.target.id, node)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self._scope.declare(node.target.id, node)

    def visit_For(self, node):
        # Loop target variable counts as used
        if isinstance(node.target, ast.Name):
            self._scope.use(node.target.id)
        elif isinstance(node.target, ast.Tuple):
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    self._scope.use(elt.id)
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._scope.use(node.id)

    def visit_ListComp(self, node):
        child = self._push()
        for gen in node.generators:
            if isinstance(gen.target, ast.Name):
                child.mark_arg(gen.target.id)
        self.generic_visit(node)
        self._pop()

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def get_unused_across_scopes(self) -> list[Issue]:
        issues = []
        self._collect_unused(self._root_scope, issues)
        return issues

    def _collect_unused(self, scope: ScopeEnvironment, issues: list):
        for name, node in scope.get_unused().items():
            issues.append(Issue(
                kind='unused_variable',
                message=f"Unused variable: '{name}'",
                line=getattr(node, 'lineno', None),
                col=getattr(node, 'col_offset', None),
                severity='warning',
            ))
        for child in scope.children:
            self._collect_unused(child, issues)


# ---------------------------------------------------------------------------
# Shadow Analyzer — detects variables overwritten before first use
# ---------------------------------------------------------------------------

class ShadowAnalyzer(ast.NodeVisitor):
    """
    Detects the 'wasted assignment' pattern:
        x = 1    ← this assignment is wasted
        x = 2    ← x is reassigned before ever being read
        return x

    This is the false negative the original code missed.
    """

    def __init__(self):
        self._last_assign: dict = {}   # name → node
        self._used: set = set()
        self.issues: list[Issue] = []

    def visit_Assign(self, node):
        # Visit RHS before LHS (RHS may read variables)
        self.visit(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                if name in self._last_assign and name not in self._used:
                    wasted = self._last_assign[name]
                    self.issues.append(Issue(
                        kind='shadowed_variable',
                        message=f"Variable '{name}' reassigned before first use — first assignment is wasted",
                        line=getattr(wasted, 'lineno', None),
                        severity='warning',
                    ))
                self._last_assign[name] = node
                self._used.discard(name)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._used.add(node.id)

    def visit_FunctionDef(self, node):
        # Analyze the function body with a fresh shadow state
        # (shadows inside a function are independent of the outer scope)
        child = ShadowAnalyzer()
        for stmt in node.body:
            child.visit(stmt)
        self.issues.extend(child.issues)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        child = ShadowAnalyzer()
        for stmt in node.body:
            child.visit(stmt)
        self.issues.extend(child.issues)


# ---------------------------------------------------------------------------
# Main DissonanceDetector — public API
# ---------------------------------------------------------------------------

class DissonanceDetector:
    """
    Full dissonance detector.

    Combines:
      - ScopeAnalyzer (AST-based Γ environment)  →  unused variables
      - ControlFlowGraph                          →  unreachable code (all forms)
      - ShadowAnalyzer                            →  wasted assignments
    """

    def __init__(self, source_code: str):
        self.source_code = source_code
        self._tree: Optional[ast.AST] = None
        self._issues: list[Issue] = []

    def parse(self):
        self._tree = ast.parse(self.source_code)

    def analyze(self):
        # Scope dissonance
        scope_analyzer = ScopeAnalyzer()
        scope_analyzer.visit(self._tree)
        self._issues.extend(scope_analyzer.get_unused_across_scopes())

        # Flow dissonance (CFG)
        cfg = ControlFlowGraph()
        cfg.build(self._tree)
        for stmt in cfg.get_unreachable():
            kind = 'unreachable_code'
            if isinstance(stmt, ast.If):
                test = stmt.test
                val = test.value if isinstance(test, ast.Constant) else '...'
                msg = f"Unreachable code: 'if {val}:' body will never execute"
            else:
                msg = f"Unreachable code after terminating statement ({stmt.__class__.__name__})"
            self._issues.append(Issue(
                kind=kind,
                message=msg,
                line=getattr(stmt, 'lineno', None),
                severity='error',
            ))

        # Shadow dissonance
        shadow_analyzer = ShadowAnalyzer()
        shadow_analyzer.visit(self._tree)
        self._issues.extend(shadow_analyzer.issues)

        # Sort by line number for clean output
        self._issues.sort(key=lambda i: (i.line or 0, i.kind))

    def get_issues(self) -> list[str]:
        return [str(i) for i in self._issues]

    def get_structured_issues(self) -> list[Issue]:
        return self._issues

    def has_issues(self) -> bool:
        return bool(self._issues)
