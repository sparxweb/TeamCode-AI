import ast
import re
from typing import List, Optional, Set
from app.models import FindingItem


SQL_KEYWORDS_PATTERN = re.compile(
    r"\b(SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|WHERE\s+\w+\s*=)\b",
    re.IGNORECASE,
)

SQL_KEYWORDS_BROAD = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b",
    re.IGNORECASE,
)

SECRET_KEY_PATTERN = re.compile(
    r"""(?i)\b([a-zA-Z0-9_]*(?:api[_-]?key|secret|password|passwd|token|auth[_-]?token|access[_-]?key|private[_-]?key|jwt[_-]?secret))\s*=\s*['"]([a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,})['"]"""
)

AWS_KEY_PATTERN = re.compile(r"""['"](AKIA[0-9A-Z]{16})['"]""")

DANGEROUS_SHELL_PATTERN = re.compile(
    r"""(?i)(os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output))\s*\(\s*(f['"].*?\{|.*?\+|.*?\%\s*|.*?\.format\().*?(shell\s*=\s*True)?"""
)

EVAL_EXEC_PATTERN = re.compile(
    r"""(?i)\b(eval|exec)\s*\(\s*(?!['"][^'"]*['"]\s*\))([a-zA-Z0-9_\.\[\]]+)\s*\)"""
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"""(?i)open\s*\(\s*(f['"].*?\{[a-zA-Z0-9_]+\}.*?['"]|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*\+\s*['"][^'"]*['"]|[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)"""
)

UNSAFE_DESERIALIZATION_PATTERN = re.compile(
    r"""(?i)(pickle\.(?:loads|load)|_pickle\.(?:loads|load)|yaml\.load\s*\([^,\)]+,\s*Loader\s*=\s*yaml\.(?:Loader|CLoader|UnsafeLoader)\))"""
)


def mask_secret(secret_str: str) -> str:
    """Masks secret to prevent exposing real keys in evidence or logs."""
    if len(secret_str) <= 8:
        return "****"
    return secret_str[:3] + "..." + "****"


class DeterministicSecurityScanner:
    """
    Lightweight, high-confidence deterministic security analyzer.
    Combines Python AST analysis and robust syntax pattern checks.
    Never executes user code.
    """

    def scan(self, code: str, language: str = "python") -> List[FindingItem]:
        findings: List[FindingItem] = []
        if not code or not code.strip():
            return findings

        lines = code.splitlines()

        # 1. AST Analysis for Python (if Python or auto or code contains Python syntax)
        is_python = language.lower() in ("python", "py", "auto", "text")
        if is_python:
            try:
                tree = ast.parse(code)
                ast_findings = self._scan_python_ast(tree, lines)
                findings.extend(ast_findings)
            except SyntaxError as se:
                if language.lower() in ("python", "py"):
                    se_line = se.lineno or 1
                    line_content = lines[se_line - 1].strip() if 0 < se_line <= len(lines) else ""
                    findings.append(
                        FindingItem(
                            rule_id="SYN001",
                            title=f"Python Syntax Error: {se.msg}",
                            category="syntax",
                            severity="critical",
                            confidence=1.0,
                            line_start=se_line,
                            line_end=getattr(se, "end_lineno", se_line) or se_line,
                            explanation=f"Python parser failed at line {se_line}: {se.msg}. The code contains invalid syntax and cannot be parsed or executed.",
                            recommended_fix=f"Correct the syntax error around line {se_line}.",
                            requires_fix=True,
                            evidence=line_content,
                            validated_by_scanner=True,
                        )
                    )

        # 2. Syntax & Regex Pattern Analysis (applies to all languages and snippets)
        regex_findings = self._scan_syntax_patterns(lines, language)

        # Merge and deduplicate by rule_id and line_start
        seen_keys = set((f.rule_id, f.line_start) for f in findings)
        for rf in regex_findings:
            if (rf.rule_id, rf.line_start) not in seen_keys:
                findings.append(rf)
                seen_keys.add((rf.rule_id, rf.line_start))

        return findings

    def _scan_python_ast(self, tree: ast.AST, lines: List[str]) -> List[FindingItem]:
        findings: List[FindingItem] = []
        tainted_query_vars: Set[str] = set()

        def _is_sql_binop_injection(binop_node: ast.BinOp) -> bool:
            """
            Checks if a BinOp tree (concatenation (+) or formatting (%)) combines
            SQL keywords with dynamic variables/expressions.
            """
            if not isinstance(binop_node.op, (ast.Add, ast.Mod)):
                return False
                
            has_sql_literal = False
            has_dynamic_part = False

            def walk_subnodes(n):
                nonlocal has_sql_literal, has_dynamic_part
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    if SQL_KEYWORDS_BROAD.search(n.value):
                        has_sql_literal = True
                elif isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.Subscript, ast.JoinedStr)):
                    has_dynamic_part = True
                elif isinstance(n, ast.BinOp):
                    walk_subnodes(n.left)
                    walk_subnodes(n.right)

            walk_subnodes(binop_node.left)
            walk_subnodes(binop_node.right)
            return has_sql_literal and has_dynamic_part

        def _is_sql_format_call(call_node: ast.Call) -> bool:
            """
            Checks if .format(...) is called on an SQL string with dynamic arguments.
            """
            if isinstance(call_node.func, ast.Attribute) and call_node.func.attr == "format":
                if isinstance(call_node.func.value, ast.Constant) and isinstance(call_node.func.value.value, str):
                    if SQL_KEYWORDS_BROAD.search(call_node.func.value.value):
                        if call_node.args or call_node.keywords:
                            return True
            return False

        class SecurityVisitor(ast.NodeVisitor):
            def visit_Assign(self, node: ast.Assign):
                line_num = getattr(node, "lineno", 1)
                line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                is_dynamic_sql = False

                # Case A: Assigned from f-string (JoinedStr)
                if isinstance(node.value, ast.JoinedStr):
                    has_formatted_val = any(isinstance(v, ast.FormattedValue) for v in node.value.values)
                    if has_formatted_val:
                        text_parts = [
                            v.value for v in node.value.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
                        ]
                        combined_text = " ".join(text_parts)
                        if SQL_KEYWORDS_BROAD.search(combined_text):
                            is_dynamic_sql = True
                            if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                                findings.append(
                                    FindingItem(
                                        rule_id="SQL001",
                                        title="SQL Injection (String Interpolation in SQL Query)",
                                        category="security",
                                        severity="high",
                                        confidence=0.98,
                                        line_start=line_num,
                                        line_end=getattr(node, "end_lineno", line_num),
                                        explanation=(
                                            "User-controlled input is directly interpolated into an SQL statement via an f-string. "
                                            "This exposes the database to severe SQL injection attacks."
                                        ),
                                        team_memory_used=[],
                                        recommended_fix="Use a parameterized query with placeholders (e.g. query = 'SELECT * FROM users WHERE username = %s', cursor.execute(query, (username,)))",
                                        requires_fix=True,
                                        evidence=line_content,
                                        validated_by_scanner=True,
                                    )
                                )

                # Case B: Assigned from string concatenation (+) or formatting (%)
                elif isinstance(node.value, ast.BinOp):
                    if _is_sql_binop_injection(node.value):
                        is_dynamic_sql = True
                        if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                            findings.append(
                                FindingItem(
                                    rule_id="SQL001",
                                    title="SQL Injection (String Concatenation / Formatting in SQL Query)",
                                    category="security",
                                    severity="high",
                                    confidence=0.98,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation=(
                                        "SQL query is constructed using string concatenation or '%' string formatting. "
                                        "User-controlled variables can alter query structure and bypass authentication."
                                    ),
                                    team_memory_used=[],
                                    recommended_fix="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )

                # Case C: Assigned from .format() call
                elif isinstance(node.value, ast.Call) and _is_sql_format_call(node.value):
                    is_dynamic_sql = True
                    if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                        findings.append(
                            FindingItem(
                                rule_id="SQL001",
                                title="SQL Injection (.format() in SQL Query)",
                                category="security",
                                severity="high",
                                confidence=0.98,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation="SQL query constructed using .format() interpolation with dynamic arguments.",
                                team_memory_used=[],
                                recommended_fix="Use parameterized queries with placeholder syntax instead of .format().",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )

                # Record variable name if dynamic SQL was assigned
                if is_dynamic_sql:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_query_vars.add(target.id)

                self.generic_visit(node)

            def visit_JoinedStr(self, node: ast.JoinedStr):
                # Also check inline f-strings not in assignments (e.g. cursor.execute(f"SELECT ..."))
                has_formatted_val = any(isinstance(v, ast.FormattedValue) for v in node.values)
                if has_formatted_val:
                    text_parts = [
                        v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    ]
                    combined_text = " ".join(text_parts)
                    if SQL_KEYWORDS_BROAD.search(combined_text):
                        line_num = getattr(node, "lineno", 1)
                        if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                            line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                            findings.append(
                                FindingItem(
                                    rule_id="SQL001",
                                    title="SQL Injection (String Interpolation in SQL Query)",
                                    category="security",
                                    severity="high",
                                    confidence=0.98,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation=(
                                        "User-controlled input is directly interpolated into an SQL statement. "
                                        "Dynamic query assembly introduces critical SQL injection vulnerabilities."
                                    ),
                                    team_memory_used=[],
                                    recommended_fix="Replace string interpolation with parameterized queries using parameter tuples.",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )
                self.generic_visit(node)

            def visit_BinOp(self, node: ast.BinOp):
                # Catch dynamic SQL concatenation in return statements, expressions, etc.
                if _is_sql_binop_injection(node):
                    line_num = getattr(node, "lineno", 1)
                    if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                        line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                        findings.append(
                            FindingItem(
                                rule_id="SQL001",
                                title="SQL Injection (String Concatenation / Formatting in SQL Query)",
                                category="security",
                                severity="high",
                                confidence=0.98,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation="SQL query constructed dynamically via string concatenation (+) or modulo (%) operator.",
                                team_memory_used=[],
                                recommended_fix="Use parameterized queries with placeholder syntax.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                line_num = getattr(node, "lineno", 1)
                line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""

                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                # 1. Check cursor.execute(dynamic_sql)
                if func_name == "execute" and node.args:
                    first_arg = node.args[0]
                    # Direct f-string passed to execute
                    if isinstance(first_arg, ast.JoinedStr):
                        if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                            findings.append(
                                FindingItem(
                                    rule_id="SQL001",
                                    title="SQL Injection (Dynamic execute() Query)",
                                    category="security",
                                    severity="high",
                                    confidence=0.99,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation="cursor.execute() called with an interpolated f-string SQL query directly.",
                                    team_memory_used=[],
                                    recommended_fix="Pass parameters as a separate tuple: cursor.execute(query, (params,))",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )
                    # Direct string concatenation/formatting passed to execute
                    elif isinstance(first_arg, ast.BinOp) and _is_sql_binop_injection(first_arg):
                        if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                            findings.append(
                                FindingItem(
                                    rule_id="SQL001",
                                    title="SQL Injection (String Concatenation in execute())",
                                    category="security",
                                    severity="high",
                                    confidence=0.98,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation="cursor.execute() called with concatenated string expressions.",
                                    team_memory_used=[],
                                    recommended_fix="Use parameterized queries instead of string concatenation in execute().",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )
                    # Direct .format() passed to execute
                    elif isinstance(first_arg, ast.Call) and _is_sql_format_call(first_arg):
                        if not any(f.rule_id == "SQL001" and f.line_start == line_num for f in findings):
                            findings.append(
                                FindingItem(
                                    rule_id="SQL001",
                                    title="SQL Injection (.format() in execute())",
                                    category="security",
                                    severity="high",
                                    confidence=0.98,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation="cursor.execute() called with .format() interpolation expression.",
                                    team_memory_used=[],
                                    recommended_fix="Pass parameters as a separate tuple: cursor.execute(query, (params,))",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )

                # 2. Check unsafe eval() / exec()
                if func_name in ("eval", "exec") and isinstance(node.func, ast.Name):
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        findings.append(
                            FindingItem(
                                rule_id="SEC_EVAL",
                                title="Unsafe Code Execution (eval/exec)",
                                category="security",
                                severity="critical",
                                confidence=0.99,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation=f"Direct invocation of {func_name}() with dynamic input enables arbitrary remote code execution.",
                                team_memory_used=[],
                                recommended_fix="Avoid eval() or exec(). Use ast.literal_eval() for safe literal evaluation or parse structured formats like JSON.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )

                # 3. Unsafe Deserialization in AST (pickle.load / loads)
                if func_name in ("loads", "load"):
                    module_name = ""
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                    if module_name in ("pickle", "_pickle", "cPickle"):
                        findings.append(
                            FindingItem(
                                rule_id="DES001",
                                title="Unsafe Deserialization (pickle)",
                                category="security",
                                severity="critical",
                                confidence=0.98,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation="Use of pickle.load/loads on untrusted data can lead to arbitrary remote code execution via object reduction (__reduce__).",
                                team_memory_used=[],
                                recommended_fix="Use safe serialization formats like JSON (json.loads) or protocol buffers instead of pickle.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )

                # 4. Dangerous Shell commands in AST (os.system, os.popen)
                if func_name in ("system", "popen") and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        findings.append(
                            FindingItem(
                                rule_id="CMD001",
                                title="Command Injection (os.system/popen)",
                                category="security",
                                severity="critical",
                                confidence=0.95,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation="Invoking system commands via os.system or os.popen with unvalidated input permits arbitrary command injection.",
                                team_memory_used=[],
                                recommended_fix="Use subprocess.run with argument list (shell=False) and validate inputs strictly.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )

                # 5. Logic: Self-Comparison
            def visit_Compare(self, node: ast.Compare):
                line_num = getattr(node, "lineno", 1)
                line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                if isinstance(node.left, ast.Name):
                    for comp in node.comparators:
                        if isinstance(comp, ast.Name) and comp.id == node.left.id:
                            findings.append(
                                FindingItem(
                                    rule_id="LOG001",
                                    title="Suspicious Self-Comparison (Always True/False)",
                                    category="logic",
                                    severity="medium",
                                    confidence=0.98,
                                    line_start=line_num,
                                    line_end=getattr(node, "end_lineno", line_num),
                                    explanation=f"Variable '{node.left.id}' is being compared against itself. This is either redundant or indicates a logic error.",
                                    recommended_fix="Verify intended comparison operands; compare against the target value rather than the same variable.",
                                    requires_fix=True,
                                    evidence=line_content,
                                    validated_by_scanner=True,
                                )
                            )
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._check_unreachable(node.body)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._check_unreachable(node.body)
                self.generic_visit(node)

            def visit_If(self, node: ast.If):
                self._check_unreachable(node.body)
                if node.orelse:
                    self._check_unreachable(node.orelse)
                self.generic_visit(node)

            def visit_For(self, node: ast.For):
                self._check_unreachable(node.body)
                self.generic_visit(node)

            def visit_Try(self, node: ast.Try):
                self._check_unreachable(node.body)
                for handler in node.handlers:
                    self._check_unreachable(handler.body)
                if node.finalbody:
                    self._check_unreachable(node.finalbody)
                self.generic_visit(node)

            def _check_unreachable(self, stmts: List[ast.stmt]):
                for i, stmt in enumerate(stmts[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise)):
                        next_stmt = stmts[i + 1]
                        line_num = getattr(next_stmt, "lineno", 1)
                        line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                        findings.append(
                            FindingItem(
                                rule_id="LOG002",
                                title="Unreachable Code Detected",
                                category="logic",
                                severity="low",
                                confidence=0.95,
                                line_start=line_num,
                                line_end=getattr(next_stmt, "end_lineno", line_num),
                                explanation="Code follows an unconditional return or raise in the same block and will never execute.",
                                recommended_fix="Remove or relocate unreachable code, or adjust the control flow condition.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )
                        break

            def visit_While(self, node: ast.While):
                line_num = getattr(node, "lineno", 1)
                line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                is_infinite_test = False
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    is_infinite_test = True
                elif isinstance(node.test, ast.Name) and node.test.id in ("True", "1"):
                    is_infinite_test = True

                if is_infinite_test:
                    has_exit = False
                    for sub in ast.walk(node):
                        if isinstance(sub, (ast.Break, ast.Return, ast.Raise)):
                            has_exit = True
                            break
                        if isinstance(sub, ast.Call):
                            func_name = ""
                            if isinstance(sub.func, ast.Name):
                                func_name = sub.func.id
                            elif isinstance(sub.func, ast.Attribute):
                                func_name = sub.func.attr
                            if func_name in ("exit", "quit"):
                                has_exit = True
                                break
                    if not has_exit:
                        findings.append(
                            FindingItem(
                                rule_id="LOG004",
                                title="Potential Infinite Loop Detected",
                                category="logic",
                                severity="high",
                                confidence=0.92,
                                line_start=line_num,
                                line_end=getattr(node, "end_lineno", line_num),
                                explanation="Loop condition is constant True with no break, return, or exception exit found in the loop body.",
                                recommended_fix="Ensure the loop has a termination condition, break statement, or timeout mechanism.",
                                requires_fix=True,
                                evidence=line_content,
                                validated_by_scanner=True,
                            )
                        )
                self.generic_visit(node)

            def visit_ExceptHandler(self, node: ast.ExceptHandler):
                line_num = getattr(node, "lineno", 1)
                line_content = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    findings.append(
                        FindingItem(
                            rule_id="QAL001",
                            title="Empty Exception Handler (Errors Silently Ignored)",
                            category="quality",
                            severity="medium",
                            confidence=0.95,
                            line_start=line_num,
                            line_end=getattr(node, "end_lineno", line_num),
                            explanation="Exception block catches errors but only contains 'pass', silently swallowing failures and obscuring critical bugs.",
                            recommended_fix="Log the exception or handle specific expected exceptions appropriately instead of silently passing.",
                            requires_fix=True,
                            evidence=line_content,
                            validated_by_scanner=True,
                        )
                    )
                self.generic_visit(node)

                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)
        return findings

    def _scan_syntax_patterns(self, lines: List[str], language: str) -> List[FindingItem]:
        findings: List[FindingItem] = []
        full_code = "\n".join(lines).lower()

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("//"):
                continue

            # 1. SQL001: f-strings or template literals with SQL keywords
            has_fstring_syntax = ("f\"" in line_str or "f'" in line_str or ("`" in line_str and "${" in line_str))
            if has_fstring_syntax:
                if SQL_KEYWORDS_BROAD.search(line_str) and ("{" in line_str and "}" in line_str):
                    findings.append(
                        FindingItem(
                            rule_id="SQL001",
                            title="SQL Injection (String Interpolation in SQL Query)",
                            category="security",
                            severity="high",
                            confidence=0.98,
                            line_start=idx,
                            line_end=idx,
                            explanation="User-controlled input is directly interpolated into an SQL statement. Exposes database to SQL injection attacks.",
                            team_memory_used=[],
                            recommended_fix="Use parameterized queries with database cursor placeholders (e.g. cursor.execute(query, (params,)))",
                            requires_fix=True,
                            evidence=line_str,
                            validated_by_scanner=True,
                        )
                    )

            # 2. SQL001: String concatenation used to construct SQL query with dynamic variables
            # e.g. query = "SELECT ... " + var or "WHERE name = '" + user + "'"
            if ("+" in line_str) and SQL_KEYWORDS_BROAD.search(line_str):
                # Ensure it's not a print or comment
                if not line_str.startswith("print"):
                    # Check for concatenation with dynamic variable (unquoted identifier)
                    sql_concat_match = re.search(
                        r"""(['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*['"][^'"]*['"])""",
                        line_str,
                        re.IGNORECASE,
                    )
                    if sql_concat_match:
                        findings.append(
                            FindingItem(
                                rule_id="SQL001",
                                title="SQL Injection (String Concatenation in SQL Query)",
                                category="security",
                                severity="high",
                                confidence=0.98,
                                line_start=idx,
                                line_end=idx,
                                explanation="SQL statement constructed using string concatenation with dynamic variables. Exposes database to SQL injection attacks.",
                                team_memory_used=[],
                                recommended_fix="Use parameterized queries with placeholders instead of string concatenation.",
                                requires_fix=True,
                                evidence=line_str,
                                validated_by_scanner=True,
                            )
                        )

            # 3. SQL001: String formatting with % operator outside quotes
            if ("%" in line_str) and SQL_KEYWORDS_BROAD.search(line_str):
                # Check for "SELECT ... " % (var,) or % var
                sql_mod_match = re.search(r"""(['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*%\s*(?:\([^\)]+\)|[a-zA-Z_][a-zA-Z0-9_]*))""", line_str, re.IGNORECASE)
                if sql_mod_match:
                    findings.append(
                        FindingItem(
                            rule_id="SQL001",
                            title="SQL Injection (String Formatting in SQL Query)",
                            category="security",
                            severity="high",
                            confidence=0.98,
                            line_start=idx,
                            line_end=idx,
                            explanation="SQL query constructed using '%' string formatting with dynamic variables. Exposes database to SQL injection attacks.",
                            team_memory_used=[],
                            recommended_fix="Use parameterized queries with cursor placeholders instead of '%' string formatting.",
                            requires_fix=True,
                            evidence=line_str,
                            validated_by_scanner=True,
                        )
                    )

            # 4. SQL001: .format() call on SQL string
            if (".format(" in line_str) and SQL_KEYWORDS_BROAD.search(line_str):
                sql_fmt_match = re.search(r"""(['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\.format\s*\([^\)]+\))""", line_str, re.IGNORECASE)
                if sql_fmt_match:
                    findings.append(
                        FindingItem(
                            rule_id="SQL001",
                            title="SQL Injection (.format() in SQL Query)",
                            category="security",
                            severity="high",
                            confidence=0.98,
                            line_start=idx,
                            line_end=idx,
                            explanation="SQL query constructed using .format() string interpolation with dynamic variables.",
                            team_memory_used=[],
                            recommended_fix="Use parameterized queries with cursor placeholders instead of .format().",
                            requires_fix=True,
                            evidence=line_str,
                            validated_by_scanner=True,
                        )
                    )

            # 3. SEC001: Hardcoded Secrets & API Keys
            secret_match = SECRET_KEY_PATTERN.search(line_str)
            if secret_match:
                key_name, secret_val = secret_match.group(1), secret_match.group(2)
                lower_val = secret_val.lower()
                is_placeholder = any(p in lower_val for p in ["your_", "example", "placeholder", "xxx", "dummy", "changeme", "test_secret"])
                is_env = any(e in line_str.lower() for e in ["os.getenv", "os.environ", "process.env", "config."])

                if not is_placeholder and not is_env and len(secret_val) >= 8:
                    masked = line_str.replace(secret_val, mask_secret(secret_val))
                    findings.append(
                        FindingItem(
                            rule_id="SEC001",
                            title="Hardcoded Credentials / Secret Detected",
                            category="security",
                            severity="critical",
                            confidence=0.95,
                            line_start=idx,
                            line_end=idx,
                            explanation=f"Potential hardcoded secret or credential assigned to variable '{key_name}'. Storing secrets in source code risks credential leakage.",
                            team_memory_used=[],
                            recommended_fix=f"Extract secret into environment variable: {key_name} = os.getenv('{key_name.upper()}')",
                            requires_fix=True,
                            evidence=masked,
                            validated_by_scanner=True,
                        )
                    )

            aws_match = AWS_KEY_PATTERN.search(line_str)
            if aws_match and "AKIA" in line_str:
                raw_aws = aws_match.group(1)
                findings.append(
                    FindingItem(
                        rule_id="SEC001",
                        title="Hardcoded AWS Access Key ID Detected",
                        category="security",
                        severity="critical",
                        confidence=0.99,
                        line_start=idx,
                        line_end=idx,
                        explanation="Hardcoded AWS Access Key ID pattern (AKIA...) detected in source code.",
                        team_memory_used=[],
                        recommended_fix="Load AWS credentials from AWS Secrets Manager, IAM roles, or AWS_ACCESS_KEY_ID environment variable.",
                        requires_fix=True,
                        evidence=line_str.replace(raw_aws, mask_secret(raw_aws)),
                        validated_by_scanner=True,
                    )
                )

            # 4. SEC_EVAL: eval() / exec() on dynamic input
            eval_match = EVAL_EXEC_PATTERN.search(line_str)
            if eval_match:
                findings.append(
                    FindingItem(
                        rule_id="SEC_EVAL",
                        title="Unsafe Code Execution (eval/exec)",
                        category="security",
                        severity="critical",
                        confidence=0.99,
                        line_start=idx,
                        line_end=idx,
                        explanation="eval() or exec() executed on dynamic input allows arbitrary remote code execution.",
                        team_memory_used=[],
                        recommended_fix="Avoid eval() or exec(). Use ast.literal_eval() for safe evaluation or parse structured formats like JSON.",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 5. CMD001: Dangerous Shell Commands
            if DANGEROUS_SHELL_PATTERN.search(line_str):
                findings.append(
                    FindingItem(
                        rule_id="CMD001",
                        title="Command Injection (Dangerous Shell Execution)",
                        category="security",
                        severity="critical",
                        confidence=0.95,
                        line_start=idx,
                        line_end=idx,
                        explanation="Shell command constructed with dynamic string interpolation or shell=True allows arbitrary OS command injection.",
                        team_memory_used=[],
                        recommended_fix="Use subprocess.run with argument list: subprocess.run(['cmd', arg], shell=False)",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 6. PATH001: Unsafe Path Construction / Path Traversal
            if PATH_TRAVERSAL_PATTERN.search(line_str):
                findings.append(
                    FindingItem(
                        rule_id="PATH001",
                        title="Path Traversal Risk (Dynamic File Path Construction)",
                        category="security",
                        severity="high",
                        confidence=0.90,
                        line_start=idx,
                        line_end=idx,
                        explanation="File path constructed directly from dynamic variables passed to open(). Can allow path traversal if inputs are unvalidated.",
                        team_memory_used=[],
                        recommended_fix="Sanitize filename with os.path.basename() or validate target path with pathlib.Path.resolve() within allowed directory.",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 7. DES001: Unsafe Deserialization
            if UNSAFE_DESERIALIZATION_PATTERN.search(line_str):
                findings.append(
                    FindingItem(
                        rule_id="DES001",
                        title="Unsafe Deserialization Pattern Detected",
                        category="security",
                        severity="critical",
                        confidence=0.96,
                        line_start=idx,
                        line_end=idx,
                        explanation="Deserializing untrusted data with pickle or unsafe yaml loaders allows arbitrary remote code execution.",
                        team_memory_used=[],
                        recommended_fix="Use json.loads() or yaml.safe_load() to parse untrusted payloads securely.",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 8. SEC_XSS: Cross-Site Scripting (XSS) via Unsafe DOM Manipulation
            if re.search(r"""(?i)(\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)""", line_str):
                findings.append(
                    FindingItem(
                        rule_id="SEC_XSS",
                        title="Cross-Site Scripting (XSS) via Unsafe DOM Manipulation",
                        category="security",
                        severity="high",
                        confidence=0.96,
                        line_start=idx,
                        line_end=idx,
                        explanation="Direct assignment to innerHTML, document.write, or dangerouslySetInnerHTML renders unescaped HTML, enabling XSS attacks.",
                        team_memory_used=[],
                        recommended_fix="Use textContent, innerText, or framework-safe sanitized DOM elements instead of raw HTML insertion.",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 9. SEC_SSRF: Potential Server-Side Request Forgery
            ssrf_match = re.search(r"""(?i)(requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|axios\.(?:get|post)|fetch)\s*\(\s*(f['"].*?\{|['"][^'"]*['"]\s*\+|[a-zA-Z_][a-zA-Z0-9_]*\s*[\),])""", line_str)
            if ssrf_match and not line_str.startswith("//") and not line_str.startswith("#"):
                if not re.search(r"""(?i)(requests\.(?:get|post)|fetch)\s*\(\s*['"]https?://""", line_str):
                    findings.append(
                        FindingItem(
                            rule_id="SEC_SSRF",
                            title="Server-Side Request Forgery (SSRF) Risk",
                            category="security",
                            severity="high",
                            confidence=0.90,
                            line_start=idx,
                            line_end=idx,
                            explanation="Network request destination URL is dynamically constructed or derived from input without target host validation or allowlisting.",
                            team_memory_used=[],
                            recommended_fix="Validate request URLs against a strict allowlist of authorized hostnames and schemes before issuing requests.",
                            requires_fix=True,
                            evidence=line_str,
                            validated_by_scanner=True,
                        )
                    )

            # 10. SEC_RANDOM: Insecure Randomness in Security Context
            is_random_call = bool(re.search(r"""(?i)(?:random\.random|random\.randint|random\.choice|Math\.random)\s*\(""", line_str))
            has_sec_line = bool(re.search(r"""(?i)\b(?:token|secret|password|passwd|key|auth|session|otp|pin|salt|nonce)\b""", line_str))
            has_sec_global = any(kw in full_code for kw in ("token", "secret", "password", "auth", "session", "otp", "nonce"))
            if is_random_call and (has_sec_line or has_sec_global):
                findings.append(
                    FindingItem(
                        rule_id="SEC_RANDOM",
                        title="Insecure Randomness Used for Security-Sensitive Value",
                        category="security",
                        severity="high",
                        confidence=0.94,
                        line_start=idx,
                        line_end=idx,
                        explanation="Pseudo-random generators (e.g. random.random or Math.random) are predictable and not cryptographically secure for keys, tokens, or passwords.",
                        team_memory_used=[],
                        recommended_fix="Use cryptographically secure randomness (e.g. secrets.token_hex(), crypto.getRandomValues, or crypto/rand).",
                        requires_fix=True,
                        evidence=line_str,
                        validated_by_scanner=True,
                    )
                )

            # 11. SEC_CRYPTO: Weak Hash Function for Passwords/Credentials
            if re.search(r"""(?i)(hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['"]md5|crypto\.createHash\(['"]sha1)\b""", line_str):
                if re.search(r"""(?i)(password|passwd|pwd|credential|secret)""", line_str):
                    findings.append(
                        FindingItem(
                            rule_id="SEC_CRYPTO",
                            title="Weak Cryptographic Hash for Sensitive Credentials",
                            category="security",
                            severity="high",
                            confidence=0.95,
                            line_start=idx,
                            line_end=idx,
                            explanation="MD5 and SHA-1 are cryptographically broken collision-vulnerable algorithms and must not be used for hashing passwords or credentials.",
                            team_memory_used=[],
                            recommended_fix="Use a modern adaptive key-derivation function such as Argon2, bcrypt, or scrypt for passwords.",
                            requires_fix=True,
                            evidence=line_str,
                            validated_by_scanner=True,
                        )
                    )

        # 12. SYN002: Unclosed Delimiters Check for Bracketed Languages
        lang_lower = language.lower()
        if lang_lower not in ("python", "py", "yaml", "yml"):
            delimiters_err = self._check_bracket_balance(lines)
            if delimiters_err:
                err_line, err_msg = delimiters_err
                err_content = lines[err_line - 1].strip() if 0 < err_line <= len(lines) else ""
                findings.append(
                    FindingItem(
                        rule_id="SYN002",
                        title="Syntax Error: Unclosed or Unmatched Delimiter",
                        category="syntax",
                        severity="critical",
                        confidence=0.98,
                        line_start=err_line,
                        line_end=err_line,
                        explanation=f"{err_msg}. Unbalanced brackets or unclosed quotes cause compilation/parse errors.",
                        recommended_fix="Ensure all brackets, parentheses, and quotes are properly paired and closed.",
                        requires_fix=True,
                        evidence=err_content,
                        validated_by_scanner=True,
                    )
                )

        return findings

    def _check_bracket_balance(self, lines: List[str]) -> Optional[tuple[int, str]]:
        stack = []
        pairs = {')': '(', '}': '{', ']': '['}
        line_map = {}

        for line_idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if line_str.startswith(("//", "#", "/*", "*")):
                continue
            for char in line:
                if char in "({[":
                    stack.append(char)
                    line_map[len(stack)] = line_idx
                elif char in ")}]":
                    if not stack or stack[-1] != pairs[char]:
                        return line_idx, f"Unmatched closing delimiter '{char}'"
                    stack.pop()

        if stack:
            open_char = stack[-1]
            last_line = line_map.get(len(stack), len(lines))
            return last_line, f"Unclosed delimiter '{open_char}'"
        return None


deterministic_scanner = DeterministicSecurityScanner()
