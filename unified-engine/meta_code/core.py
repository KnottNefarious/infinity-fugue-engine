"""
core.py — Core data structures for the Infinity × Fugue Unified Engine.

Two categories of findings:
  - Issue: structural dissonance (unused vars, unreachable code, wasted assignments)
  - Finding: security dissonance (Γ ⊢ φ fails on safety proof)

Both flow through the same DissonanceReport and are tracked by the same
Banach convergence machinery in resolution.py.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


# ── Structural Dissonance ─────────────────────────────────────────────────────

@dataclass
class Issue:
    """A structural contradiction — Γ cannot prove the program is internally consistent."""
    kind: str               # 'unused_variable' | 'unreachable_code' | 'shadowed_variable'
    message: str
    line: Optional[int] = None
    col: Optional[int] = None
    severity: str = 'warning'   # 'error' | 'warning' | 'info'

    def __str__(self):
        loc = f" (line {self.line})" if self.line else ""
        return f"{self.message}{loc}"

    def __hash__(self):
        return hash((self.kind, self.message, self.line))

    def __eq__(self, other):
        if not isinstance(other, Issue):
            return False
        return (self.kind, self.message, self.line) == (other.kind, other.message, other.line)


# ── Security Dissonance ───────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    A security contradiction — Γ cannot prove 'input at sink S is safe.'
    Carries the full attack path for report generation.
    """
    vuln_type: str
    severity: str           # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    path: List[str]         # Attack path: ['request', 'get', 'uid', 'cursor.execute']
    sink: str               # Human-readable sink description
    reason: str             # Why this is a vulnerability
    fix: str                # Suggested remediation
    lineno: Optional[int] = None
    exploitability: str = 'UNKNOWN'
    exploit_reason: str = ''
    halstead_weight: float = 1.0   # Severity multiplier from Halstead V

    def format(self) -> str:
        location = f"Location: line {self.lineno}\n" if self.lineno else ""
        weight_note = f"\nComplexity Weight: {self.halstead_weight:.2f}x" if self.halstead_weight != 1.0 else ""
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"{location}"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}\n"
            f"Exploitability: {self.exploitability} — {self.exploit_reason}"
            f"{weight_note}"
        )

    def __hash__(self):
        return hash((self.vuln_type, self.lineno, self.sink))

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return (self.vuln_type, self.lineno, self.sink) == (other.vuln_type, other.lineno, other.sink)


# ── Program ───────────────────────────────────────────────────────────────────

class Program:
    def __init__(self, name: str, version: str = '1.0',
                 source_code: Optional[str] = None,
                 ast_tree=None):
        self.name = name
        self.version = version
        self.source_code = source_code
        self.ast_tree = ast_tree
        self.signatures: List['SemanticSignature'] = []

    def add_signature(self, signature: 'SemanticSignature'):
        self.signatures.append(signature)


class SemanticSignature:
    def __init__(self, signature_id: str, description: str,
                 compressed_form=None, node_types=None):
        self.signature_id = signature_id
        self.description = description
        self.compressed_form = compressed_form or []
        self.node_types = node_types or {}


# ── Dissonance Report ─────────────────────────────────────────────────────────

class DissonanceReport:
    """
    The unified output of a full Infinity × Fugue analysis run.
    Contains both structural and security dissonance, plus all mathematical metrics.
    """

    def __init__(self, report_id: str, program: Program, issues: List[str]):
        self.report_id = report_id
        self.program = program

        # Structural dissonance (code quality)
        self.issues: List[str] = issues

        # Security dissonance (Stage 3 output)
        self.security_findings: List[Finding] = []

        # Mathematical analysis
        self.complexity_metrics: Dict[str, Any] = {}
        self.structural_analysis: Dict[str, Any] = {}

        # Convergence tracking
        self.resolution_predictions: List[Dict] = []
        self.convergence: Dict[str, Any] = {}

        # Structural identity
        self.structural_fingerprint: tuple = ()

        # Optional runtime verification
        self.execution_result: Optional[Dict] = None

    def add_issue(self, issue: str):
        self.issues.append(issue)

    def add_finding(self, finding: Finding):
        self.security_findings.append(finding)

    @property
    def is_clean(self) -> bool:
        return len(self.issues) == 0 and len(self.security_findings) == 0

    def summary(self) -> str:
        return (
            f"Report: {self.report_id}\n"
            f"Security Findings: {len(self.security_findings)}\n"
            f"Structural Issues: {len(self.issues)}\n"
            f"Clean: {self.is_clean}"
        )
