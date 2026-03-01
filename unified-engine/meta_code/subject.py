"""
subject.py — The Subject: Generating Function  G(x) = Σ aₙxⁿ

In the Infinity × Fugue framework, the Subject is the core generator of the
sequence — the f(n) that drives the whole structure.

For code, we define:
    aₙ = node-type distribution at AST depth n
    G(x) = Σ aₙxⁿ

Rather than flattening all nodes into one distribution, we keep the depth
index. This gives us a polynomial whose coefficients describe the code's
shape at each level of nesting.

Two programs with the same G(x) are structurally isomorphic —
different performances of the same fugue.
"""

import ast
from collections import Counter, defaultdict


class SubjectExtractor:
    """
    Extracts the generating function of a program's structure.

    G(x) = Σ aₙxⁿ   where   aₙ = node_type_distribution at depth n

    This is the 'Subject' of the fugue — the core pattern that
    everything else is built from and compared against.
    """

    def __init__(self, source_code: str):
        self.source_code = source_code
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.source_code)

    def _walk_with_depth(self, node, depth=0):
        yield node, depth
        for child in ast.iter_child_nodes(node):
            yield from self._walk_with_depth(child, depth + 1)

    def extract_subject(self) -> list[dict]:
        """
        Returns the depth-indexed structural distribution.
        Index n of the list = aₙ = Counter of node types at depth n.
        The full list is G — the generating function of the code's shape.
        """
        self._parse()
        depth_dist = defaultdict(Counter)
        for node, depth in self._walk_with_depth(self._tree):
            depth_dist[depth][node.__class__.__name__] += 1

        if not depth_dist:
            return []
        max_depth = max(depth_dist.keys())
        return [dict(depth_dist[d]) for d in range(max_depth + 1)]

    def compute_polynomial(self, x: float = 0.5) -> float:
        """
        Evaluate G(x) = Σ aₙxⁿ at a given x (default 0.5).
        aₙ is the total node count at depth n (scalar coefficient).

        The result is a structural fingerprint scalar. Two structurally
        identical programs produce the same value for all x.
        """
        gf = self.extract_subject()
        return sum(
            sum(counts.values()) * (x ** n)
            for n, counts in enumerate(gf)
        )

    def identify_core_pattern(self) -> list:
        """
        The dominant node type at each depth — the 'melodic line' of the fugue.
        This is what the AI identifies first: the Subject's primary theme.
        """
        gf = self.extract_subject()
        return [
            max(level.items(), key=lambda kv: kv[1])[0] if level else None
            for level in gf
        ]

    def structural_fingerprint(self) -> tuple:
        """
        A hashable fingerprint derived from G(x).
        Two programs with the same fingerprint are structurally isomorphic —
        they are transpositions of each other in the fugue sense.
        """
        gf = self.extract_subject()
        return tuple(
            tuple(sorted(level.items()))
            for level in gf
        )

    def self_similarity_score(self) -> float:
        """
        Measures how much the structure repeats itself across depth levels.
        High score = fractal/recursive structure (Bach-like fugue).
        Low score = flat, non-repeating structure.

        Computed as average Jaccard similarity between consecutive depth levels.
        """
        gf = self.extract_subject()
        if len(gf) < 2:
            return 0.0

        similarities = []
        for i in range(len(gf) - 1):
            set_a = set(gf[i].keys())
            set_b = set(gf[i + 1].keys())
            union = set_a | set_b
            if not union:
                continue
            intersection = set_a & set_b
            similarities.append(len(intersection) / len(union))

        return round(sum(similarities) / len(similarities), 4) if similarities else 0.0
