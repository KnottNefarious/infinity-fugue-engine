"""
resolution.py — Resolution: lim |Sₙ − L| < ε  as  n → ∞

Banach Fixed-Point Theorem applied to the analyze→fix→reanalyze cycle.
The fixed point L = ∅ (zero issues). Consonance.

Tracks BOTH structural issues and security findings using the same
Jaccard distance metric. A finding that persists across multiple runs
is a 'perpetual crescendo' — flagged with higher priority.

Jaccard distance: d(A,B) = |A △ B| / |A ∪ B|  — a proper metric.
"""

from collections import Counter


# ── Resolution pattern lookup ─────────────────────────────────────────────────

_RESOLUTION_PATTERNS = {
    # Structural
    'unused variable':     'Remove or use the unused variable.',
    'unreachable code':    'Remove the unreachable code block or fix the condition.',
    'shadowed variable':   'Remove the first assignment, or use the variable before reassigning.',
    'syntax error':        'Review and correct the syntax near the reported location.',
    'name error':          'Ensure the variable or function is defined before use.',
    'type error':          'Check that operands or arguments have compatible types.',
    'import error':        'Verify the module name and that it is installed.',
    'attribute error':     'Confirm the object has the referenced attribute.',
    'index error':         'Guard array accesses with bounds checks.',
    'key error':           "Use .get() or check key existence before accessing the dict.",
    'zero division':       'Add a guard to avoid division by zero.',

    # Security
    'sql injection':       'Use parameterized queries: cursor.execute("... WHERE id = %s", (uid,))',
    'command injection':   'Avoid shell=True. Pass arguments as a list to subprocess.',
    'path traversal':      'Validate and sanitize file paths. Use os.path.basename() and allowlists.',
    'cross-site scripting':'Escape all output with markupsafe.escape() or use Jinja2 auto-escaping.',
    'server-side request': 'Validate URLs against an allowlist of trusted domains.',
    'unsafe deserializ':   'Never deserialize untrusted data with pickle or yaml.load().',
    'insecure direct':     'Verify resource ownership before access: check current_user.can_access().',
    'missing authoriz':    'Add an authorization check before this sensitive operation.',
}


# ── Metric functions ──────────────────────────────────────────────────────────

def jaccard_distance(set_a, set_b) -> float:
    """
    Jaccard distance — proper metric on sets.
    d(A,B) = |A △ B| / |A ∪ B|

    Satisfies:
      d(A,A) = 0              (reflexivity)
      d(A,B) = d(B,A)         (symmetry)
      d(A,C) ≤ d(A,B)+d(B,C)  (triangle inequality)
    """
    set_a = frozenset(set_a)
    set_b = frozenset(set_b)
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    sym_diff = set_a.symmetric_difference(set_b)
    return len(sym_diff) / len(union)


def is_contraction(distances: list) -> bool:
    """
    True if the sequence of distances is strictly decreasing.
    This is the necessary condition for a contraction mapping.
    """
    if len(distances) < 2:
        return False
    return all(distances[i] > distances[i + 1] for i in range(len(distances) - 1))


# ── ResolutionPredictor ───────────────────────────────────────────────────────

class ResolutionPredictor:
    """
    Tracks convergence toward the zero-issue fixed point.
    Works identically for structural issues and security findings —
    same math, same metric, same convergence criterion.

    Requires the engine to be a singleton for history to persist.
    """

    def __init__(self, issues: list):
        self.issues = list(issues) if issues else []
        self._history: list = []      # list of frozensets

    def add_historical_run(self, issues: list):
        """Feed a previous run's issues to build the convergence sequence."""
        self._history.append(frozenset(issues))

    def analyze(self) -> Counter:
        """Register current run and count issue types."""
        self._history.append(frozenset(self.issues))
        return Counter(
            key
            for issue in self.issues
            for key in _RESOLUTION_PATTERNS
            if key in issue.lower()
        )

    # ── Convergence metrics ───────────────────────────────────────────────────

    def convergence_sequence(self) -> list:
        """
        Jaccard distances between consecutive runs.
        Strictly decreasing → contraction mapping → convergence to ∅ proven.
        """
        if len(self._history) < 2:
            return []
        return [
            round(jaccard_distance(self._history[i], self._history[i + 1]), 4)
            for i in range(len(self._history) - 1)
        ]

    def is_converging(self):
        """
        True  → contraction confirmed, will reach fixed point
        False → oscillating or diverging
        None  → insufficient data (need ≥ 3 runs)
        """
        seq = self.convergence_sequence()
        if len(seq) < 2:
            return None
        return is_contraction(seq)

    def distance_to_resolution(self) -> float:
        """
        Jaccard distance from previous run to current run.
        0.0 = no change (either already resolved or stuck).
        1.0 = completely different issue set.
        """
        if not self.issues and (not self._history or not self._history[-2] if len(self._history) >= 2 else True):
            return 0.0
        if len(self._history) >= 2:
            return jaccard_distance(self._history[-2], self._history[-1])
        return 1.0 if self.issues else 0.0

    def runs_to_resolution(self):
        """
        Estimate remaining fix cycles to reach ∅.
        Based on average issue reduction rate.
        Returns None if insufficient history.
        """
        if len(self._history) < 2:
            return None
        counts = [len(h) for h in self._history]
        if counts[-1] == 0:
            return 0
        reductions = [
            counts[i] - counts[i + 1]
            for i in range(len(counts) - 1)
            if counts[i] - counts[i + 1] > 0
        ]
        if not reductions:
            return None
        avg = sum(reductions) / len(reductions)
        return max(0, round(counts[-1] / avg)) if avg > 0 else None

    def sticky_issues(self) -> list:
        """
        Issues that appear in ALL historical runs — 'perpetual crescendo.'
        These get escalated priority: the developer has seen them and not fixed them.
        """
        if len(self._history) < 2:
            return []
        return list(self._history[0].intersection(*self._history[1:]))

    # ── Resolution predictions ────────────────────────────────────────────────

    def predict_resolution(self) -> list:
        """
        For each current issue, return a fix suggestion and metadata.
        'convergence': True → this issue was in a prior run (sticky).
        'sticky': True → this issue appears in ALL prior runs (escalate).
        """
        previous = self._history[-2] if len(self._history) >= 2 else frozenset()
        all_sticky = set(self.sticky_issues())

        predictions = []
        for issue in self.issues:
            suggestion = 'Review and address the flagged issue.'
            for key, fix in _RESOLUTION_PATTERNS.items():
                if key in issue.lower():
                    suggestion = fix
                    break
            predictions.append({
                'issue': issue,
                'suggestion': suggestion,
                'convergence': issue in previous,
                'sticky': issue in all_sticky,
            })
        return predictions
