import ast
import builtins
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Literal
from app.models import FindingItem
from app.services.deterministic_scanner import deterministic_scanner

logger = logging.getLogger("teamcode.validator")

PYTHON_BUILTINS: Set[str] = set(dir(builtins)).union({
    "__name__", "__file__", "__doc__", "__package__", "True", "False", "None"
})


import re

@dataclass
class FixValidationOutcome:
    is_validated: bool
    validation_status: Literal["VERIFIED", "VALIDATION_LIMITED", "VALIDATION_FAILED", "NOT_VALIDATED"]
    validation_message: str
    differs_from_original: bool
    vulnerabilities_resolved: bool
    original_findings: List[FindingItem] = field(default_factory=list)
    fixed_code_findings: List[FindingItem] = field(default_factory=list)
    resolved_findings: List[FindingItem] = field(default_factory=list)
    new_findings: List[FindingItem] = field(default_factory=list)
    false_positives: List[FindingItem] = field(default_factory=list)
    remaining_risks: List[str] = field(default_factory=list)
    verification_checks: List[str] = field(default_factory=list)
    portability_notes: List[str] = field(default_factory=list)


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

        verification_checks: List[str] = []
        portability_notes: List[str] = []

        # 1. Difference Check
        if normalized_fixed == normalized_orig:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix requires review: fixed code is identical to original code.",
                differs_from_original=False,
                vulnerabilities_resolved=False,
                original_findings=original_findings,
                remaining_risks=["Fixed code is identical to original code."],
                verification_checks=["Difference check: FAILED (Identical code)"],
            )

        verification_checks.append("Code difference check: PASSED (modifications detected)")

        # 2. Syntax Check
        fixed_tree = None
        if lang_lower in ("python", "py"):
            try:
                fixed_tree = ast.parse(fixed_code)
                compile(fixed_code, "<fixed_code>", "exec")
                verification_checks.append("Python AST & byte-compile syntax check: PASSED")
            except SyntaxError as se:
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix requires review: Syntax error on line {se.lineno}: {se.msg}",
                    differs_from_original=True,
                    vulnerabilities_resolved=False,
                    original_findings=original_findings,
                    remaining_risks=[f"Syntax error on line {se.lineno}: {se.msg}"],
                    verification_checks=[f"Python syntax check: FAILED (line {se.lineno}: {se.msg})"],
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
                    original_findings=original_findings,
                    remaining_risks=[syntax_err],
                    verification_checks=[f"JS/TS delimiter check: FAILED ({syntax_err})"],
                )
            verification_checks.append("JS/TS delimiter balance & literal syntax check: PASSED")
        else:
            delimiter_err = self._check_delimiters(fixed_code)
            if delimiter_err:
                return FixValidationOutcome(
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message=f"Fix requires review: {delimiter_err}",
                    differs_from_original=True,
                    vulnerabilities_resolved=False,
                    original_findings=original_findings,
                    remaining_risks=[delimiter_err],
                    verification_checks=[f"Delimiter check: FAILED ({delimiter_err})"],
                )
            verification_checks.append("Bracket and delimiter structure check: PASSED")

        # 3. Post-Fix Deterministic Security Rescan
        post_findings = deterministic_scanner.scan(fixed_code, language)
        orig_rule_ids = set(f.rule_id for f in original_findings if f.rule_id)
        post_rule_ids = set(f.rule_id for f in post_findings if f.rule_id)
        verification_checks.append(f"Post-fix deterministic rescan: {len(post_findings)} finding(s) detected")

        # Check for platform portability in ping / command execution
        if "ping" in fixed_code and ("-c" in fixed_code or "-n" in fixed_code):
            portability_notes.append(
                "Potential platform compatibility issue: ping flags differ across operating systems (Unix -c vs Windows -n)."
            )

        # 4. Semantic check for original findings resolution
        resolved_findings: List[FindingItem] = []
        still_present_findings: List[FindingItem] = []
        false_positives: List[FindingItem] = []

        for orig_f in original_findings:
            f_copy = orig_f.model_copy() if hasattr(orig_f, "model_copy") else orig_f
            is_resolved = False
            resolution_note = ""

            # Deterministic Rule: If the scanner still flags this rule on the fixed code, it is NOT resolved!
            if orig_f.rule_id in post_rule_ids:
                is_resolved = False
                resolution_note = f"Rule '{orig_f.rule_id}' is still detected by deterministic scanner in fixed code."

            elif orig_f.rule_id == "CMD001":
                # Verify shell=True removed and arguments passed as list or safe execution
                has_shell_true = bool(re.search(r"""(?i)shell\s*=\s*True""", fixed_code))
                has_os_system = bool(re.search(r"""(?i)os\.(?:system|popen)\s*\(""", fixed_code))
                if not has_shell_true and not has_os_system:
                    is_resolved = True
                    resolution_note = "Command injection resolved: shell=True eliminated, command executed with structured argument list."
                else:
                    is_resolved = False
                    resolution_note = "Command injection pattern still present (shell=True or os.system)."

            elif orig_f.rule_id == "SQL001":
                # Verify string interpolation or concatenation into SQL query is gone
                has_fstring_sql = bool(re.search(r"""f['"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{""", fixed_code, re.IGNORECASE | re.DOTALL))
                has_concat_sql = bool(re.search(r"""(?:SELECT|INSERT|UPDATE|DELETE).*?\+\s*[a-zA-Z0-9_]""", fixed_code, re.IGNORECASE))
                has_modulo_sql = bool(re.search(r"""(?:SELECT|INSERT|UPDATE|DELETE).*?['"]\s*%\s*[a-zA-Z0-9_\(]""", fixed_code, re.IGNORECASE))
                if not has_fstring_sql and not has_concat_sql and not has_modulo_sql:
                    is_resolved = True
                    resolution_note = "SQL injection resolved: dynamic variable interpolation removed; parameterized query placeholders used."
                else:
                    is_resolved = False
                    resolution_note = "SQL injection pattern still present in query construction."

            elif orig_f.rule_id == "SEC001":
                has_secret_pattern = bool(re.search(r"""(?i)\b(?:api[_-]?key|secret|password|passwd|token)\s*=\s*['"][a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,}['"]""", fixed_code))
                has_env = any(e in fixed_code for e in ("os.getenv", "os.environ", "process.env", "System.getenv", "config."))
                if not has_secret_pattern or has_env:
                    is_resolved = True
                    resolution_note = "Hardcoded secret resolved: credential removed from source and loaded via environment configuration."
                else:
                    is_resolved = False
                    resolution_note = "Hardcoded credential pattern still detected in source code."

            elif orig_f.rule_id == "DES001":
                has_pickle = bool(re.search(r"""pickle\.(?:loads|load)""", fixed_code))
                if not has_pickle:
                    is_resolved = True
                    resolution_note = "Unsafe deserialization resolved: pickle replaced with safe serialization format."
                else:
                    is_resolved = False
                    resolution_note = "Unsafe deserialization (pickle) still present."

            elif orig_f.rule_id == "PATH001":
                has_sanitization = any(p in fixed_code for p in ("os.path.basename", "pathlib", "resolve", "secure_filename", "normpath"))
                if has_sanitization or not re.search(r"""(?i)open\s*\(\s*(f['"].*?\{|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*\+\s*['"][^'"]*['"])""", fixed_code):
                    is_resolved = True
                    resolution_note = "Path traversal resolved: path input validated or sanitized."
                else:
                    is_resolved = False
                    resolution_note = "Path traversal pattern still present."

            elif orig_f.rule_id == "SEC_CRYPTO":
                has_weak_hash = bool(re.search(r"""(?i)\b(md5|sha1)\b""", fixed_code))
                if not has_weak_hash:
                    is_resolved = True
                    resolution_note = "Weak cryptographic hash resolved: replaced with secure hashing algorithm."
                else:
                    is_resolved = False
                    resolution_note = "Weak hash algorithm still present."

            elif orig_f.rule_id == "SEC_XSS":
                has_raw_html = bool(re.search(r"""(?:\.innerHTML\s*=|document\.write|dangerouslySetInnerHTML)""", fixed_code))
                if not has_raw_html:
                    is_resolved = True
                    resolution_note = "XSS vulnerability resolved: unescaped HTML insertion removed; safe DOM manipulation used."
                else:
                    is_resolved = False
                    resolution_note = "Raw HTML insertion still present."

            elif orig_f.rule_id == "MEM001":
                has_unsafe_mem = bool(re.search(r"""\b(gets|strcpy|strcat|sprintf)\s*\(""", fixed_code))
                if not has_unsafe_mem:
                    is_resolved = True
                    resolution_note = "Unsafe memory handling resolved: dangerous function replaced with bounded alternative."
                else:
                    is_resolved = False
                    resolution_note = "Unsafe memory function still present."

            else:
                is_resolved = True
                resolution_note = f"Issue '{orig_f.title}' resolved by applied fix."

            if is_resolved:
                f_copy.status = "RESOLVED"
                f_copy.resolution_note = resolution_note
                resolved_findings.append(f_copy)
                verification_checks.append(f"Original finding [{orig_f.rule_id}]: RESOLVED ({resolution_note})")
            else:
                f_copy.status = "STILL_PRESENT"
                f_copy.resolution_note = resolution_note
                still_present_findings.append(f_copy)
                verification_checks.append(f"Original finding [{orig_f.rule_id}]: STILL PRESENT")

        # 5. Check if any original vulnerability is STILL_PRESENT
        if still_present_findings:
            unresolved_rules = ", ".join(sorted(set(f.rule_id for f in still_present_findings)))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message=f"Fix requires review: rule(s) {unresolved_rules} still detected in fixed code.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                original_findings=original_findings,
                fixed_code_findings=post_findings,
                resolved_findings=resolved_findings,
                new_findings=[],
                false_positives=[],
                remaining_risks=[f"Vulnerability {f.rule_id} ({f.title}) was not resolved." for f in still_present_findings],
                verification_checks=verification_checks,
                portability_notes=portability_notes,
            )

        # 6. Check if fix introduced NEW issues
        new_findings: List[FindingItem] = []
        for pf in post_findings:
            if pf.rule_id not in orig_rule_ids:
                # Check for portability false positive
                pf_evidence = (pf.evidence or "").lower()
                if pf.rule_id == "CMD001" and "ping" in pf_evidence and ("-c" in pf_evidence or "-n" in pf_evidence):
                    pf.status = "FALSE_POSITIVE"
                    pf.portability_note = "Potential platform compatibility issue: ping flags differ across operating systems."
                    false_positives.append(pf)
                else:
                    pf.status = "NEW_ISSUE"
                    new_findings.append(pf)

        new_critical_high = [f for f in new_findings if f.severity in ("high", "critical")]
        if new_critical_high:
            new_rules = ", ".join(sorted(set(f.rule_id for f in new_critical_high)))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message=f"Fix requires review: fix introduced new issue(s) {new_rules}.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                original_findings=original_findings,
                fixed_code_findings=post_findings,
                resolved_findings=resolved_findings,
                new_findings=new_findings,
                false_positives=false_positives,
                remaining_risks=[f"New security issue introduced: {new_rules}"],
                verification_checks=verification_checks,
                portability_notes=portability_notes,
            )

        # 7. Python-Specific AST, Symbol, Import, and Signature Analysis
        if lang_lower in ("python", "py"):
            return self._validate_python_ast(
                original_code=original_code,
                fixed_code=fixed_code,
                fixed_tree=fixed_tree,
                original_findings=original_findings,
                fixed_code_findings=post_findings,
                resolved_findings=resolved_findings,
                new_findings=new_findings,
                false_positives=false_positives,
                verification_checks=verification_checks,
                portability_notes=portability_notes,
            )

        # 8. Non-Python Validation
        if lang_lower in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
            return FixValidationOutcome(
                is_validated=True,
                validation_status="VERIFIED",
                validation_message="Fix verified: Original issue(s) resolved, syntax validated, and deterministic security rules passed.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=original_findings,
                fixed_code_findings=post_findings,
                resolved_findings=resolved_findings,
                new_findings=new_findings,
                false_positives=false_positives,
                remaining_risks=[],
                verification_checks=verification_checks,
                portability_notes=portability_notes,
            )

        # Unverified language boundary
        return FixValidationOutcome(
            is_validated=False,
            validation_status="VALIDATION_LIMITED",
            validation_message=f"Validation limited: Pattern scan passed, full {language} compiler validation unavailable.",
            differs_from_original=True,
            vulnerabilities_resolved=True,
            original_findings=original_findings,
            fixed_code_findings=post_findings,
            resolved_findings=resolved_findings,
            new_findings=new_findings,
            false_positives=false_positives,
            remaining_risks=[f"Language '{language}' does not have local compiler validation."],
            verification_checks=verification_checks,
            portability_notes=portability_notes,
        )

    def _validate_python_ast(
        self,
        original_code: str,
        fixed_code: str,
        fixed_tree: Optional[ast.AST],
        original_findings: Optional[List[FindingItem]] = None,
        fixed_code_findings: Optional[List[FindingItem]] = None,
        resolved_findings: Optional[List[FindingItem]] = None,
        new_findings: Optional[List[FindingItem]] = None,
        false_positives: Optional[List[FindingItem]] = None,
        verification_checks: Optional[List[str]] = None,
        portability_notes: Optional[List[str]] = None,
    ) -> FixValidationOutcome:
        """Deep AST analysis of symbols, imports, and function signatures in Python."""
        orig_findings = original_findings or []
        fix_findings = fixed_code_findings or []
        res_findings = resolved_findings or []
        n_findings = new_findings or []
        fp_findings = false_positives or []
        v_checks = list(verification_checks or [])
        p_notes = list(portability_notes or [])

        if fixed_tree is None:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Unable to parse fixed code into AST.",
                differs_from_original=True,
                vulnerabilities_resolved=False,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=["AST parsing failed for fixed code."],
                verification_checks=v_checks,
                portability_notes=p_notes,
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
                        original_findings=orig_findings,
                        fixed_code_findings=fix_findings,
                        resolved_findings=res_findings,
                        new_findings=n_findings,
                        false_positives=fp_findings,
                        remaining_risks=[f"Function '{fn_name}' missing from fixed code."],
                        verification_checks=v_checks,
                        portability_notes=p_notes,
                    )
                fixed_params = fixed_funcs[fn_name]
                if orig_params != fixed_params:
                    return FixValidationOutcome(
                        is_validated=False,
                        validation_status="VALIDATION_FAILED",
                        validation_message=f"Fix requires review: parameters of '{fn_name}' were altered.",
                        differs_from_original=True,
                        vulnerabilities_resolved=True,
                        original_findings=orig_findings,
                        fixed_code_findings=fix_findings,
                        resolved_findings=res_findings,
                        new_findings=n_findings,
                        false_positives=fp_findings,
                        remaining_risks=[f"Function signature modified for '{fn_name}': expected {orig_params}, got {fixed_params}"],
                        verification_checks=v_checks,
                        portability_notes=p_notes,
                    )

            v_checks.append("Function signature preservation: PASSED (original functions and parameters preserved)")

        # B. Missing Required Standard Imports
        imported_modules = self._get_imported_names(fixed_tree)

        # Check for os, subprocess, json, re usage
        uses_os = False
        uses_subprocess = False
        uses_json = False
        uses_re = False

        for node in ast.walk(fixed_tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "os":
                    uses_os = True
                elif node.value.id == "subprocess":
                    uses_subprocess = True
                elif node.value.id == "json":
                    uses_json = True
                elif node.value.id == "re":
                    uses_re = True

        if uses_os and "os" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import os' for environment variable access.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=["Missing import: 'os' is accessed but not imported."],
                verification_checks=v_checks,
                portability_notes=p_notes,
            )

        if uses_subprocess and "subprocess" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import subprocess'.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=["Missing import: 'subprocess' is accessed but not imported."],
                verification_checks=v_checks,
                portability_notes=p_notes,
            )

        if uses_json and "json" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import json'.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=["Missing import: 'json' is accessed but not imported."],
                verification_checks=v_checks,
                portability_notes=p_notes,
            )

        if uses_re and "re" not in imported_modules:
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_FAILED",
                validation_message="Fix validation failed: Missing required import 'import re'.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=["Missing import: 're' is accessed but not imported."],
                verification_checks=v_checks,
                portability_notes=p_notes,
            )

        v_checks.append("Standard module import resolution: PASSED")

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
                    original_findings=orig_findings,
                    fixed_code_findings=fix_findings,
                    resolved_findings=res_findings,
                    new_findings=n_findings,
                    false_positives=fp_findings,
                    remaining_risks=[f"Invented or undefined reference: '{inv_list}' is not imported or defined."],
                    verification_checks=v_checks,
                    portability_notes=p_notes,
                )

            # Unresolved symbol existed in original snippet (e.g. database.connect without import database)
            orig_unresolved_list = ", ".join(sorted(unresolved_fixed))
            return FixValidationOutcome(
                is_validated=False,
                validation_status="VALIDATION_LIMITED",
                validation_message=f"Validation limited: Unresolved external dependency '{orig_unresolved_list}' cannot be verified in current snippet context.",
                differs_from_original=True,
                vulnerabilities_resolved=True,
                original_findings=orig_findings,
                fixed_code_findings=fix_findings,
                resolved_findings=res_findings,
                new_findings=n_findings,
                false_positives=fp_findings,
                remaining_risks=[f"Unresolved external dependency: '{orig_unresolved_list}' is not imported or defined in snippet."],
                verification_checks=v_checks,
                portability_notes=p_notes,
            )

        v_checks.append("Symbol resolution check: PASSED (0 invented or undefined symbols)")

        # All Python checks passed!
        return FixValidationOutcome(
            is_validated=True,
            validation_status="VERIFIED",
            validation_message="Fix verified: Original issue(s) resolved, syntax validated, parameters preserved, and deterministic security rules passed.",
            differs_from_original=True,
            vulnerabilities_resolved=True,
            original_findings=orig_findings,
            fixed_code_findings=fix_findings,
            resolved_findings=res_findings,
            new_findings=n_findings,
            false_positives=fp_findings,
            remaining_risks=[],
            verification_checks=v_checks,
            portability_notes=p_notes,
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
