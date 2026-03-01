"""
transposition.py — Transposition:  F : C ≅ D

In music, transposition moves the same melody to a different key.
In the Infinity × Fugue framework, it maps the structural DNA of one
problem domain to another, allowing solutions from D to apply in C.

For code: if two programs share the same structural generating function G(x),
they are isomorphic — the same fugue in a different key.

The original TranspositionFinder did set-level comparison only (which node
types appear). This version adds:

  1. DEPTH-LEVEL COMPARISON: Does the structure match at each depth? Two
     programs can share all node types but have them at completely different
     depths — that's a different fugue, not a transposition.

  2. RELATIONSHIP PRESERVATION: A true categorical isomorphism F: C ≅ D
     preserves morphisms (parent→child relationships), not just objects
     (node types). We check whether the call graph and nesting patterns match.

  3. SIMILARITY SCORE BREAKDOWN: Instead of one number, we give similarity
     at the type level, depth level, and pattern level separately.

Practical use: if codebase A has a known bug pattern at a specific structural
location and codebase B is isomorphic to A via F, we can predict where
the same class of bug would appear in B. That's the cross-domain transposition
from the framework description — applied to codebases instead of physics domains.
"""

import ast
from collections import Counter
from meta_code.subject import SubjectExtractor


class TranspositionFinder:
    """
    Compare two programs' structural DNA.
    Finds the functor F : C ≅ D — or measures how far from isomorphic they are.
    """

    def __init__(self):
        pass

    def _node_type_sequence(self, source: str) -> list:
        tree = ast.parse(source)
        return [node.__class__.__name__ for node in ast.walk(tree)]

    def _call_graph(self, source: str) -> dict:
        """Map function names to the functions they call."""
        tree = ast.parse(source)
        graph = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            calls.append(child.func.id)
                        elif isinstance(child.func, ast.Attribute):
                            calls.append(child.func.attr)
                graph[node.name] = calls
        return graph

    def find_transpositions(self, program1: str, program2: str) -> dict:
        """
        Full structural comparison between two programs.
        Returns a dict describing the isomorphism (or lack thereof).
        """
        # --- Type-level comparison (original) ---
        seq1 = self._node_type_sequence(program1)
        seq2 = self._node_type_sequence(program2)
        set1 = set(seq1)
        set2 = set(seq2)
        counts1 = Counter(seq1)
        counts2 = Counter(seq2)
        shared = set1 & set2
        union = set1 | set2
        type_similarity = len(shared) / len(union) if union else 1.0

        isomorphic_nodes = {
            n: (counts1[n], counts2[n])
            for n in shared if counts1[n] == counts2[n]
        }
        divergent_nodes = {
            n: (counts1.get(n, 0), counts2.get(n, 0))
            for n in ((shared - set(isomorphic_nodes)) | (set1 - set2) | (set2 - set1))
        }

        # --- Depth-level comparison (new) ---
        sub1 = SubjectExtractor(program1)
        sub2 = SubjectExtractor(program2)
        gf1 = sub1.extract_subject()
        gf2 = sub2.extract_subject()
        depth_similarities = self._depth_similarity(gf1, gf2)
        fp1 = sub1.structural_fingerprint()
        fp2 = sub2.structural_fingerprint()
        fingerprint_match = (fp1 == fp2)

        # --- Call graph comparison (new) ---
        cg1 = self._call_graph(program1)
        cg2 = self._call_graph(program2)
        call_graph_similarity = self._graph_similarity(cg1, cg2)

        # --- Overall isomorphism score ---
        overall = round(
            0.4 * type_similarity +
            0.4 * (sum(depth_similarities) / len(depth_similarities) if depth_similarities else 0.0) +
            0.2 * call_graph_similarity,
            4
        )

        verdict = (
            'isomorphic' if fingerprint_match else
            'strongly similar' if overall > 0.8 else
            'partially similar' if overall > 0.5 else
            'structurally distinct'
        )

        return {
            'type_similarity': round(type_similarity, 4),
            'depth_similarity': depth_similarities,
            'call_graph_similarity': round(call_graph_similarity, 4),
            'overall_similarity': overall,
            'fingerprint_match': fingerprint_match,
            'verdict': verdict,
            'shared_node_types': sorted(shared),
            'only_in_program1': sorted(set1 - set2),
            'only_in_program2': sorted(set2 - set1),
            'isomorphic_nodes': isomorphic_nodes,
            'divergent_nodes': divergent_nodes,
        }

    def _depth_similarity(self, gf1: list, gf2: list) -> list[float]:
        """
        Jaccard similarity between generating functions at each depth level.
        Both GFs may have different lengths; compare up to min(len(gf1), len(gf2)).
        """
        similarities = []
        max_depth = max(len(gf1), len(gf2))
        for i in range(max_depth):
            d1 = set(gf1[i].keys()) if i < len(gf1) else set()
            d2 = set(gf2[i].keys()) if i < len(gf2) else set()
            union = d1 | d2
            if not union:
                continue
            inter = d1 & d2
            similarities.append(round(len(inter) / len(union), 4))
        return similarities

    def _graph_similarity(self, g1: dict, g2: dict) -> float:
        """
        Compare two call graphs by their structure (not function names).
        Compares the degree sequence (number of calls per function).
        """
        if not g1 and not g2:
            return 1.0
        if not g1 or not g2:
            return 0.0
        # Compare sorted degree sequences
        deg1 = sorted(len(v) for v in g1.values())
        deg2 = sorted(len(v) for v in g2.values())
        # Pad to same length
        max_len = max(len(deg1), len(deg2))
        deg1 += [0] * (max_len - len(deg1))
        deg2 += [0] * (max_len - len(deg2))
        # Normalized difference
        total = sum(max(a, b) for a, b in zip(deg1, deg2))
        diff = sum(abs(a - b) for a, b in zip(deg1, deg2))
        return round(1 - (diff / total), 4) if total > 0 else 1.0


# ---------------------------------------------------------------------------
# StructuralAnalyzer (unchanged API, enhanced internals)
# ---------------------------------------------------------------------------

class StructuralAnalyzer:
    """Analyze a single program's structural metrics."""

    def _depth(self, node) -> int:
        children = list(ast.iter_child_nodes(node))
        if not children:
            return 1
        return 1 + max(self._depth(c) for c in children)

    def analyze_structure(self, source: str) -> dict:
        tree = ast.parse(source)
        node_types = Counter(node.__class__.__name__ for node in ast.walk(tree))
        total = sum(node_types.values())
        branching = (
            node_types.get('If', 0) + node_types.get('For', 0) +
            node_types.get('While', 0) + node_types.get('Try', 0)
        )
        depth = self._depth(tree)
        branching_factor = branching / total if total > 0 else 0.0
        signature = tuple(sorted(node_types.items()))
        return {
            'depth': depth,
            'total_nodes': total,
            'branching_factor': round(branching_factor, 4),
            'node_type_distribution': dict(node_types),
            'structural_signature': signature,
        }
