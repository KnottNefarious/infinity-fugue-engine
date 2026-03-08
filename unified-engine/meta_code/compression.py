"""
compression.py — Infinite Compression:  K(x) = min { |p| : U(p) = x }

The 'Fugal Score' is the shortest program that generates the infinite sequence.
For code analysis, K(x) approximates how much information is in the structure —
not the variable names or literal values, but the shape itself.

Two additions to the original:

1. NORMALIZED KOLMOGOROV: The original code had a ratio > 1.0 bug for small
   inputs because zlib has a fixed header overhead. We fix this by normalizing
   against a same-length random-string baseline. A random string is maximally
   incompressible (K → 1.0), so our normalized ratio is meaningful:
     < 0.4 → low complexity (repetitive, regular structure — short fugal score)
     0.4–0.7 → medium complexity
     > 0.7 → high complexity (dense, irregular — long fugal score)

2. HALSTEAD METRICS: Software science metrics that connect directly to
   information theory — the same territory as Kolmogorov complexity.
   Volume V = (N₁+N₂)·log₂(n₁+n₂) is the information content of the program.
   These give the complexity section real scientific grounding.
"""

import ast
import math
import random
import string
import zlib
from collections import Counter


# ---------------------------------------------------------------------------
# Halstead Metrics
# ---------------------------------------------------------------------------

class HalsteadMetrics:
    """
    Halstead software science metrics.

    n₁ = distinct operators
    n₂ = distinct operands
    N₁ = total operators
    N₂ = total operands

    Volume      V = (N₁+N₂) · log₂(n₁+n₂)     information content
    Difficulty  D = (n₁/2)  · (N₂/n₂)          cognitive load
    Effort      E = D · V                        comprehension effort
    Time        T = E / 18  seconds              estimated time
    Bugs        B = V / 3000                     estimated defect density
    """

    # Operators: control structures, binary ops, comparison ops, call/attribute
    OPERATOR_NODES = (
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
        ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd, ast.MatMult,
        ast.And, ast.Or, ast.Not, ast.Invert, ast.UAdd, ast.USub,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Is, ast.IsNot, ast.In, ast.NotIn,
        ast.If, ast.For, ast.While, ast.With, ast.Return, ast.Yield,
        ast.YieldFrom, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete,
        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
        ast.Import, ast.ImportFrom, ast.Raise, ast.Try, ast.Assert,
        ast.Global, ast.Nonlocal, ast.Attribute, ast.Subscript, ast.Call,
    )

    def __init__(self, source_code: str):
        self.source_code = source_code
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.source_code)

    def compute(self) -> dict:
        self._parse()
        operators = []
        operands = []

        for node in ast.walk(self._tree):
            if isinstance(node, self.OPERATOR_NODES):
                operators.append(node.__class__.__name__)
            elif isinstance(node, ast.Name):
                operands.append(node.id)
            elif isinstance(node, ast.Constant):
                operands.append(repr(node.value))

        n1 = len(set(operators))
        n2 = len(set(operands))
        N1 = len(operators)
        N2 = len(operands)

        vocabulary = n1 + n2
        length = N1 + N2

        volume = length * math.log2(vocabulary) if vocabulary > 1 else 0.0
        difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0.0
        effort = difficulty * volume
        time_seconds = effort / 18
        bugs = volume / 3000

        return {
            'n1_distinct_operators': n1,
            'n2_distinct_operands': n2,
            'N1_total_operators': N1,
            'N2_total_operands': N2,
            'vocabulary': vocabulary,
            'length': length,
            'volume': round(volume, 2),
            'difficulty': round(difficulty, 2),
            'effort': round(effort, 2),
            'time_seconds': round(time_seconds, 2),
            'estimated_bugs': round(bugs, 4),
        }


# ---------------------------------------------------------------------------
# Pattern Extractor (unchanged, still useful for human-readable breakdown)
# ---------------------------------------------------------------------------

class PatternExtractor:
    """Extract recurring structural patterns — the 'voices' of the fugue."""

    def __init__(self, data: str):
        self.data = data
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.data)

    def extract_patterns(self) -> dict:
        self._parse()
        patterns = {
            'loops': 0, 'conditionals': 0, 'function_defs': 0,
            'function_calls': 0, 'variable_assignments': 0,
            'imports': 0, 'class_defs': 0, 'return_statements': 0,
            'try_except': 0,
        }
        for node in ast.walk(self._tree):
            if isinstance(node, (ast.For, ast.While)):
                patterns['loops'] += 1
            elif isinstance(node, ast.If):
                patterns['conditionals'] += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                patterns['function_defs'] += 1
            elif isinstance(node, ast.Call):
                patterns['function_calls'] += 1
            elif isinstance(node, ast.Assign):
                patterns['variable_assignments'] += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                patterns['imports'] += 1
            elif isinstance(node, ast.ClassDef):
                patterns['class_defs'] += 1
            elif isinstance(node, ast.Return):
                patterns['return_statements'] += 1
            elif isinstance(node, ast.Try):
                patterns['try_except'] += 1
        return patterns


# ---------------------------------------------------------------------------
# Program Compressor (structural form — name/literal stripped)
# ---------------------------------------------------------------------------

class ProgramCompressor:
    """
    Compress a program to its minimal structural representation.
    This is the 'Fugal Score' — the generating rules without the performance.
    """

    def __init__(self, program: str):
        self.program = program
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.program)

    def _structural_form(self, node):
        node_type = node.__class__.__name__
        children = [self._structural_form(c) for c in ast.iter_child_nodes(node)]
        return (node_type, tuple(children)) if children else (node_type,)

    def compress(self):
        self._parse()
        return self._structural_form(self._tree)


# ---------------------------------------------------------------------------
# Kolmogorov Complexity (normalized)
# ---------------------------------------------------------------------------

class KolmogorovComplexity:
    """
    Normalized Kolmogorov complexity estimate.

    K(x) = min { |p| : U(p) = x }

    True K(x) is uncomputable (Rice's theorem). We approximate via:
      1. Strip names/literals → pure structural form (the generating program p)
      2. zlib-compress at max level
      3. Normalize against a same-length random-string baseline

    Normalization fixes the original bug where ratio > 1.0 appeared for
    small inputs (zlib header overhead). A random string is maximally
    incompressible, so dividing by its compressed size gives a proper [0,1] range.

    Interpretation:
      0.0 – 0.4  →  low complexity  (repetitive, regular — short fugal score)
      0.4 – 0.7  →  medium complexity
      0.7 – 1.0  →  high complexity (dense, irregular — long fugal score)
    """

    _RANDOM_SEED = 42  # for reproducible normalization baseline

    def __init__(self, data: str):
        self.data = data

    def _zlib_size(self, s: str) -> int:
        return len(zlib.compress(s.encode('utf-8'), level=9))

    def compute_complexity(self) -> dict:
        compressor = ProgramCompressor(self.data)
        structural = str(compressor.compress())
        raw_size = len(structural.encode('utf-8'))
        compressed_size = self._zlib_size(structural)

        if raw_size > 0:
            # Reproducible random baseline of same length
            rng = random.Random(self._RANDOM_SEED)
            alphabet = string.ascii_lowercase + '(),\' '
            random_str = ''.join(rng.choices(alphabet, k=raw_size))
            random_compressed = self._zlib_size(random_str)
            normalized = compressed_size / random_compressed if random_compressed > 0 else 1.0
            normalized = min(normalized, 1.0)  # cap at 1.0
        else:
            normalized = 0.0

        if normalized < 0.4:
            interpretation = 'low complexity (repetitive/regular structure)'
        elif normalized < 0.7:
            interpretation = 'medium complexity'
        else:
            interpretation = 'high complexity (dense/irregular structure)'

        return {
            'raw_size': raw_size,
            'compressed_size': compressed_size,
            'raw_ratio': round(compressed_size / raw_size, 4) if raw_size > 0 else 0.0,
            'normalized_ratio': round(normalized, 4),
            'complexity': round(normalized, 4),   # alias for external consumers
            'value': round(normalized, 4),         # alias for external consumers
            'interpretation': interpretation,
        }
