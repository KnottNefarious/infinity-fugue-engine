"""
meta_engine.py — The Infinity × Fugue Orchestrator

Implements the full seven-stage pipeline:

  Stage 0: Parse          — validate syntax, build AST
  Stage 1: Subject        — G(x) = Σ aₙxⁿ  (depth-indexed generating function)
  Stage 2: Dissonance     — Γ ⊢ ϕ  (CFG + scope: structural contradictions)
  Stage 3: Security       — Γ ⊢ ϕ  (taint × CFG: security contradictions)
  Stage 4: Compression    — K(x) normalized + Halstead metrics
  Stage 5: Structure      — depth, branching, node distribution
  Stage 6: Resolution     — Banach convergence tracking + fix predictions
  Stage 7: Execution      — optional sandboxed runtime verification

SINGLETON DESIGN
The engine must be instantiated once and reused across all requests.
Convergence tracking requires history to persist across runs.
Use MetaCodeEngine.get_instance() — never instantiate directly in route handlers.
"""

import ast

from meta_code.core import DissonanceReport, Finding, Program, SemanticSignature
from meta_code.subject import SubjectExtractor
from meta_code.dissonance import DissonanceDetector
from meta_code.taint import PathSensitiveTaintAnalyzer
from meta_code.compression import KolmogorovComplexity, PatternExtractor, ProgramCompressor, HalsteadMetrics
from meta_code.transposition import StructuralAnalyzer, TranspositionFinder
from meta_code.resolution import ResolutionPredictor
from meta_code.execution import HarmonicExecutor


class MetaCodeEngine:
    """
    Infinity × Fugue Unified Analysis Engine.

    Use MetaCodeEngine.get_instance() to get the singleton.
    Use orchestrate(source_code) for full analysis.
    Use compare(source_a, source_b) for transposition analysis.
    """

    _instance = None

    def __init__(self):
        self._history_quality: list = []       # structural issue sets per run
        self._history_security: list = []      # security finding sets per run
        self._run_count: int = 0

    @classmethod
    def get_instance(cls) -> 'MetaCodeEngine':
        """
        Singleton accessor.
        Ensures convergence history persists across all requests in server lifetime.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset the singleton — for testing only."""
        cls._instance = None

    def orchestrate(
        self,
        source_code: str,
        program_name: str = 'program',
        program_version: str = '1.0',
        execute: bool = False,
    ) -> DissonanceReport:
        """
        Run the full Infinity × Fugue pipeline on source_code.

        Parameters
        ----------
        source_code     Python source to analyze
        program_name    Identifier for this program (used in report IDs)
        program_version Version string
        execute         If True, run code in sandboxed executor and include
                        runtime variable states in the report

        Returns
        -------
        DissonanceReport with all analysis fields populated
        """
        self._run_count += 1

        # ── Stage 0: Parse ───────────────────────────────────────────────────
        if not source_code or not source_code.strip():
            return self._empty_report(program_name)

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return self._syntax_error_report(str(e), program_name)

        program = Program(
            name=program_name,
            version=program_version,
            source_code=source_code,
            ast_tree=tree,
        )

        # ── Stage 1: Subject — G(x) = Σ aₙxⁿ ───────────────────────────────
        subject = SubjectExtractor(source_code)
        generating_function = subject.extract_subject()
        polynomial_value = subject.compute_polynomial()
        core_pattern = subject.identify_core_pattern()
        fingerprint = subject.structural_fingerprint()
        self_similarity = subject.self_similarity_score()

        # ── Stage 2: Dissonance — structural contradictions ──────────────────
        detector = DissonanceDetector(source_code)
        detector.parse()
        detector.analyze()
        quality_issues = detector.get_issues()
        structured_issues = detector.get_structured_issues()

        # ── Stage 3: Security — taint × CFG ─────────────────────────────────
        taint_analyzer = PathSensitiveTaintAnalyzer()
        security_findings = taint_analyzer.analyze(tree)

        # ── Stage 4: Compression — K(x) + Halstead ──────────────────────────
        patterns = PatternExtractor(source_code).extract_patterns()
        kc_result = KolmogorovComplexity(source_code).compute_complexity()
        halstead = HalsteadMetrics(source_code).compute()
        kc_result['patterns'] = patterns
        kc_result['halstead'] = halstead

        # Apply Halstead severity weighting to security findings
        halstead_volume = halstead.get('volume', 0.0)
        security_findings = self._apply_halstead_weights(security_findings, halstead_volume)

        # ── Stage 5: Structure ───────────────────────────────────────────────
        structure = StructuralAnalyzer().analyze_structure(source_code)
        structure['generating_function'] = generating_function
        structure['polynomial_value'] = round(polynomial_value, 4)
        structure['core_pattern'] = core_pattern
        structure['self_similarity'] = self_similarity

        # ── Stage 6: Resolution — Banach convergence ─────────────────────────
        # Track quality issues
        self._history_quality.append(quality_issues)
        quality_predictor = ResolutionPredictor(quality_issues)
        for past in self._history_quality[:-1]:
            quality_predictor.add_historical_run(past)
        quality_predictor.analyze()

        # Track security findings
        security_strs = [f.vuln_type + (f' line {f.lineno}' if f.lineno else '')
                        for f in security_findings]
        self._history_security.append(security_strs)
        security_predictor = ResolutionPredictor(security_strs)
        for past in self._history_security[:-1]:
            security_predictor.add_historical_run(past)
        security_predictor.analyze()

        # Mark sticky security findings (perpetual crescendo)
        sticky = set(security_predictor.sticky_issues())
        for f in security_findings:
            key = f.vuln_type + (f' line {f.lineno}' if f.lineno else '')
            if key in sticky:
                f.severity = 'CRITICAL'  # Escalate sticky findings

        convergence = {
            'run_number': self._run_count,
            # Quality convergence
            'quality': {
                'sequence': quality_predictor.convergence_sequence(),
                'is_converging': quality_predictor.is_converging(),
                'distance': round(quality_predictor.distance_to_resolution(), 4),
                'runs_remaining': quality_predictor.runs_to_resolution(),
                'sticky_issues': quality_predictor.sticky_issues(),
            },
            # Security convergence
            'security': {
                'sequence': security_predictor.convergence_sequence(),
                'is_converging': security_predictor.is_converging(),
                'distance': round(security_predictor.distance_to_resolution(), 4),
                'runs_remaining': security_predictor.runs_to_resolution(),
                'sticky_findings': security_predictor.sticky_issues(),
            },
            # Combined (backward compatible)
            'sequence': quality_predictor.convergence_sequence(),
            'is_converging': quality_predictor.is_converging(),
            'distance_to_resolution': round(quality_predictor.distance_to_resolution(), 4),
            'estimated_runs_remaining': quality_predictor.runs_to_resolution(),
        }

        # ── Stage 7: Execution — optional runtime verification ───────────────
        execution_result = None
        if execute:
            executor = HarmonicExecutor()
            execution_result = executor.execute(source_code)
            # Cross-check: static false positive detection
            if execution_result.get('success') and execution_result.get('variables'):
                runtime_vars = set(execution_result['variables'].keys())
                static_unused = {
                    i.message.split("'")[1]
                    for i in structured_issues
                    if i.kind == 'unused_variable' and "'" in i.message
                }
                false_positives = static_unused & runtime_vars
                if false_positives:
                    execution_result['static_false_positives'] = list(false_positives)

        # ── Assemble Report ───────────────────────────────────────────────────
        compressed_form = list(ProgramCompressor(source_code).compress())
        signature = SemanticSignature(
            signature_id=f"{program_name}-sig-{self._run_count}",
            description="Structural generating function signature",
            compressed_form=compressed_form,
            node_types=structure.get('node_type_distribution', {}),
        )
        program.add_signature(signature)

        # Combine all issues for unified convergence display
        all_issues_str = quality_issues + security_strs

        report = DissonanceReport(
            report_id=f"{program_name}-report-{self._run_count}",
            program=program,
            issues=quality_issues,
        )
        report.security_findings = security_findings
        report.complexity_metrics = kc_result
        report.structural_analysis = structure
        report.resolution_predictions = quality_predictor.predict_resolution()
        report.security_resolution = security_predictor.predict_resolution()
        report.convergence = convergence
        report.structural_fingerprint = fingerprint
        report.execution_result = execution_result

        return report

    def compare(self, source_a: str, source_b: str) -> dict:
        """
        Transposition: F : C ≅ D
        Find the structural isomorphism (or divergence) between two programs.
        """
        finder = TranspositionFinder()
        return finder.find_transpositions(source_a, source_b)

    def _apply_halstead_weights(self, findings: list, volume: float) -> list:
        """
        Apply Halstead Volume as a severity weight to security findings.

        V < 100:  low complexity  → weight 1.0
        V < 500:  medium          → weight 1.2
        V < 1000: high            → weight 1.5
        V >= 1000: very high      → weight 2.0

        High complexity functions are statistically more likely to contain
        co-located bugs (Halstead 1977, empirically validated).
        """
        if volume < 100:
            weight = 1.0
        elif volume < 500:
            weight = 1.2
        elif volume < 1000:
            weight = 1.5
        else:
            weight = 2.0

        for f in findings:
            f.halstead_weight = weight

        return findings

    def _empty_report(self, program_name: str) -> DissonanceReport:
        """Return an empty report for empty input."""
        program = Program(name=program_name, version='1.0')
        report = DissonanceReport(
            report_id=f"{program_name}-empty",
            program=program,
            issues=[],
        )
        report.complexity_metrics = {}
        report.structural_analysis = {}
        report.resolution_predictions = []
        report.convergence = {'run_number': self._run_count}
        report.structural_fingerprint = ()
        report.execution_result = None
        return report

    def _syntax_error_report(self, error_msg: str, program_name: str) -> DissonanceReport:
        """Return a structured report for syntax errors — never raises."""
        program = Program(name=program_name, version='1.0')
        report = DissonanceReport(
            report_id=f"{program_name}-syntax-error",
            program=program,
            issues=[f"Syntax error: {error_msg}"],
        )
        report.complexity_metrics = {}
        report.structural_analysis = {}
        report.resolution_predictions = [{
            'issue': f"Syntax error: {error_msg}",
            'suggestion': 'Review and correct the syntax near the reported location.',
            'convergence': False,
            'sticky': False,
        }]
        report.convergence = {'run_number': self._run_count}
        report.structural_fingerprint = ()
        report.execution_result = None
        return report
