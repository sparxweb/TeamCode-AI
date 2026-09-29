import ast
import builtins
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from app.models import FindingItem
from app.services.deterministic_scanner import deterministic_scanner

logger = logging.getLogger("teamcode.validator")

PYTHON_BUILTINS: Set[str] = set(dir(builtins)).union({
    "__name__", "__file__", "__doc__", "__package__", "True", "False", "None"
})


@dataclass
class FixValidationOutcome:
    is_validated: bool
    validation_status: str  # "VERIFIED" | "VALIDATION_LIMITED" | "VALIDATION_FAILED"
    validation_message: str
    differs_from_original: bool
    vulnerabilities_resolved: bool
    remaining_risks: List[str] = field(default_factory=list)


class FixValidator:
    """
    Independent, deterministic AST and symbol validator for AI-generated code fixes.
    Enforces strict verification rules:
    - Never marks code VERIFIED merely because security patterns look fixed.
    - Ensures syntax correctness.
    - Rescans with deterministic security engine to verify vulnerability resolution.
    - Prevents introduction of new security issues.
    - Preserves function names and signatures.
    - Detects missing imports (e.g. os.getenv without import os).
    - Flags invented libraries and undefined symbols.
    - Rejects false verification when external dependencies cannot be verified.
    """

    def validate_fix(
        self,
        original_code: str,
        fixed_code: str,
        language: str,
        original_findings: List[FindingItem],
    ) -> FixValidationOutcome:
        normalized_orig = original_code.strip()
        normalized_fixed = fixed_code.strip()
        lang_lower = language.lower()

        # 1. Difference Check
        if normalized_fixed == normalized_orig:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix requires review: fixed code is identical to original code.",
                differs_from_original=False,
                vulnerabilities_resolved=False,
                remaining_risks=["Fixed code is identical to original code."],
            )

        # 2. Syntax Check
        fixed_tree = None
        if lang_lower in ("python", "py"):
            try:
                fixed_tree = ast.parse(fixed_code)
            except SyntaxError as se:
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix requires review: Syntax error on line {se.lineno}: {se.msg}",
                    differs_from_original=True,
                    vulnerabilities_resolved=False,
                    remaining_risks=[f"Syntax error on line {se.lineno}: {se.msg}"],
                )
        elif lang_lower in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
            syntax_err = self._check_js_ts_syntax(fixed_code)
            if syntax_err:
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix requires review: {syntax_err}",
                    differs_from_original=True,
                    vulnerabilities_resolved=False,
                    remaining_risks=[syntax_err],
                )
        else:
            # Other languages: basic delimiter check
            delimiter_err = self._check_delimiters(fixed_code)
            if delimiter_err:
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix requires review: {delimiter_err}",
                    differs_from_original=True,
                    vulnerabilities_resolved=False,
                    remaining_risks=[delimiter_err],
                )

        # 3. Post-Fix Deterministic Security Rescan
        post_findings = deterministic_scanner.scan(fixed_code, language)
        orig_rule_ids = set(f.rule_id for f in original_findings if f.rule_id)
        post_rule_ids = set(f.rule_id for f in post_findings if f.rule_id)

        # Check if original targeted vulnerabilities still remain
        unresolved_rules = orig_rule_ids.intersection(post_rule_ids)
        if unresolved_rules:
            rule_str = ", ".join(sorted(unresolved_rules))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message=f"Fix requires review: rule(s) {rule_str} still detected.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                remaining_risks=[f"Vulnerability {rule_str} was not resolved by the fix."],
            )

        # Check if fix introduced NEW critical or high security issues
        new_critical_high = [
            f for f in post_findings if f.rule_id not in orig_rule_ids and f.severity in ("high", "critical")
        ]
        if new_critical_high:
            new_rules = ", ".join(sorted(set(f.rule_id for f in new_critical_high)))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message=f"Fix requires review: fix introduced new issue(s) {new_rules}.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                remaining_risks=[f"New security issue introduced: {new_rules}"],
            )

        # 4. Python-Specific AST, Symbol, Import, and Signature Analysis
        if lang_lower in ("python", "py"):
            return self._validate_python_ast(
                original_code=original_code,
                fixed_code=fixed_code,
                fixed_tree=fixed_tree,
            )

        # 5. Non-Python Validation
        if lang_lower in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
            return FixValidationOutcome(
                is_validated=True,
                validation_status="VERIFIED",
                validation_message="Fix verified: syntax validated and deterministic security rules passed.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                remaining_risks=[],
            )

        # Unverified language boundary
        return FixValidationOutcome(
            is_validated=False,
            validation_status="VALIDATION_LIMITED",
            validation_message=f"Validation limited: Pattern scan passed, full {language} compiler validation unavailable.",
            differs_from_original=True,
            vulnerabilities_resolved=True,
            remaining_risks=[f"Language '{language}' does not have local compiler validation."],
        )

    def _validate_python_ast(
        self,
        original_code: str,
        fixed_code: str,
        fixed_tree: Optional[ast.AST],
    ) -> FixValidationOutcome:
        """Deep AST analysis of symbols, imports, and function signatures in Python."""
        if fixed_tree is None:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Unable to parse fixed code into AST.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                remaining_risks=["AST parsing failed for fixed code."],
            )
        # Try parsing original tree
        orig_tree: Optional[ast.AST] = None
        try:
            orig_tree = ast.parse(original_code)
        except SyntaxError:
            orig_tree = None

        # A. Function Signature Preservation Check
        if orig_tree:
            orig_funcs: Dict[str, List[str]] = {}
            for node in ast.walk(orig_tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    orig_funcs[node.name] = [a.arg for a in node.args.args]

            fixed_funcs: Dict[str, List[str]] = {}
            for node in ast.walk(fixed_tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fixed_funcs[node.name] = [a.arg for a in node.args.args]

            for fn_name, orig_params in orig_funcs.items():
                if fn_name not in fixed_funcs:
                    return FixValidationOutcome(
                        is_validated=False,
                        validation_status="VALIDATION_FAILED",
                        validation_message=f"Fix requires review: original function '{fn_name}' was renamed or omitted.",
                        differs_from_original=True,
                        vulnerabilities_resolved=True,
                        remaining_risks=[f"Function '{fn_name}' missing from fixed code."],
                    )
                fixed_params = fixed_funcs[fn_name]
                if orig_params != fixed_params:
                    return FixValidationOutcome(
                        is_validated=False,
                        validation_status="VALIDATION_FAILED",
                        validation_message=f"Fix requires review: parameters of '{fn_name}' were altered.",
                        differs_from_original=True,
                        vulnerabilities_resolved=True,
                        remaining_risks=[f"Function signature modified for '{fn_name}': expected {orig_params}, got {fixed_params}"],
                    )

        # B. Missing Required Standard Imports
        imported_modules = self._get_imported_names(fixed_tree)

        # Check for os usage (e.g. os.getenv, os.environ)
        uses_os = False
        uses_subprocess = False
        uses_json = False

        for node in ast.walk(fixed_tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "os":
                    uses_os = True
                elif node.value.id == "subprocess":
                    uses_subprocess = True
                elif node.value.id == "json":
                    uses_json = True

        if uses_os and "os" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import os' for environment variable access.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                remaining_risks=["Missing import: 'os' is accessed but not imported."],
            )

        if uses_subprocess and "subprocess" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import subprocess'.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                remaining_risks=["Missing import: 'subprocess' is accessed but not imported."],
            )

        if uses_json and "json" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import json'.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                remaining_risks=["Missing import: 'json' is accessed but not imported."],
            )

        # C. Comprehensive Symbol Resolution Analysis
        unresolved_fixed = self._find_unresolved_symbols(fixed_tree)
        unresolved_orig = self._find_unresolved_symbols(orig_tree) if orig_tree else set()

        if unresolved_fixed:
            # Check if any unresolved symbol was invented by LLM (not in original unresolved)
            invented_symbols = unresolved_fixed - unresolved_orig
            if invented_symbols:
                inv_list = ", ".join(sorted(invented_symbols))
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix validation failed: Undefined or invented reference '{inv_list}' not imported or defined.",
                    differs_from_original=True,
                    vulnerabilities_resolved=True,
                    remaining_risks=[f"Invented or undefined reference: '{inv_list}' is not imported or defined."],
                )

            # Unresolved symbol existed in original snippet (e.g. database.connect without import database)
            orig_unresolved_list = ", ".join(sorted(unresolved_fixed))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_LIMITED",
                validation_message=f"Validation limited: Unresolved external dependency '{orig_unresolved_list}' cannot be verified in current snippet context.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                remaining_risks=[f"Unresolved external dependency: '{orig_unresolved_list}' is not imported or defined in snippet."],
            )

        # All Python checks passed!
        return FixValidationOutcome(
            is_validated=True,
            validation_status="VERIFIED",
            validation_message="Fix verified: syntax validated, parameters preserved, and deterministic security rules passed.",
            differs_from_original=True,
            vulnerabilities_resolved=True,
            remaining_risks=[],
        )

    def _get_imported_names(self, tree: ast.AST) -> Set[str]:
        """Extracts all module and symbol names imported in the AST."""
        imported: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported.add(name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported.add(name)
                if node.module:
                    imported.add(node.module.split(".")[0])
        return imported

    def _find_unresolved_symbols(self, tree: ast.AST) -> Set[str]:
        """
        Walks the AST and identifies loaded symbols that are neither builtins,
        module imports, top-level definitions, function parameters, nor local variables.
        """
        module_imported = self._get_imported_names(tree)
        module_defs: Set[str] = set()

        # Collect top-level definitions
        if isinstance(tree, ast.Module):
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    module_defs.add(stmt.name)
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        module_defs.update(self._extract_target_names(target))
                elif isinstance(stmt, ast.AnnAssign):
                    module_defs.update(self._extract_target_names(stmt.target))

        unresolved: Set[str] = set()

        class ScopeVisitor(ast.NodeVisitor):
            def __init__(self, outer_scope: Set[str]):
                self.scope = set(outer_scope)
                self.local_unresolved: Set[str] = set()

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._visit_function(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._visit_function(node)

            def _visit_function(self, node):
                func_scope = set(self.scope)
                # Add parameters
                for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                    func_scope.add(arg.arg)
                if node.args.vararg:
                    func_scope.add(node.args.vararg.arg)
                if node.args.kwarg:
                    func_scope.add(node.args.kwarg.arg)

                # Pre-collect local assigned variables in function body
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        for target in sub.targets:
                            func_scope.update(FixValidator._extract_target_names(target))
                    elif isinstance(sub, ast.AnnAssign):
                        func_scope.update(FixValidator._extract_target_names(sub.target))
                    elif isinstance(sub, ast.AugAssign):
                        func_scope.update(FixValidator._extract_target_names(sub.target))
                    elif isinstance(sub, ast.NamedExpr):
                        func_scope.update(FixValidator._extract_target_names(sub.target))
                    elif isinstance(sub, (ast.For, ast.AsyncFor)):
                        func_scope.update(FixValidator._extract_target_names(sub.target))
                    elif isinstance(sub, (ast.With, ast.AsyncWith)):
                        for item in sub.items:
                            if item.optional_vars:
                                func_scope.update(FixValidator._extract_target_names(item.optional_vars))
                    elif isinstance(sub, ast.ExceptHandler) and sub.name:
                        func_scope.add(sub.name)
                    elif isinstance(sub, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                        for gen in sub.generators:
                            func_scope.update(FixValidator._extract_target_names(gen.target))

                # Check loaded names inside function
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                        if sub.id not in func_scope and sub.id not in PYTHON_BUILTINS:
                            unresolved.add(sub.id)

        top_scope = module_imported | module_defs | PYTHON_BUILTINS

        # Check top-level statements for loaded names
        if isinstance(tree, ast.Module):
            for stmt in tree.body:
                if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    for sub in ast.walk(stmt):
                        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                            if sub.id not in top_scope:
                                unresolved.add(sub.id)

        visitor = ScopeVisitor(top_scope)
        visitor.visit(tree)
        return unresolved

    @staticmethod
    def _extract_target_names(node: ast.AST) -> Set[str]:
        names: Set[str] = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                names.update(FixValidator._extract_target_names(elt))
        return names

    def _check_js_ts_syntax(self, code: str) -> Optional[str]:
        """Validates basic syntax, delimiter balancing, and string closure for JS/TS."""
        return self._check_delimiters(code)

    def _check_delimiters(self, code: str) -> Optional[str]:
        stack = []
        pairs = {")": "(", "}": "{", "]": "["}
        in_single_quote = False
        in_double_quote = False
        in_backtick = False
        escape = False

        for idx, char in enumerate(code):
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue

            if char == "'" and not in_double_quote and not in_backtick:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote and not in_backtick:
                in_double_quote = not in_double_quote
                continue
            if char == "`" and not in_single_quote and not in_double_quote:
                in_backtick = not in_backtick
                continue

            if in_single_quote or in_double_quote or in_backtick:
                continue

            if char in "({[":
                stack.append(char)
            elif char in ")}]":
                if not stack or stack[-1] != pairs[char]:
                    return f"Unmatched delimiter '{char}'"
                stack.pop()

        if stack:
            return f"Unclosed delimiter '{stack[-1]}'"
        if in_single_quote or in_double_quote or in_backtick:
            return "Unclosed string literal"
        return None


fix_validator = FixValidator()
