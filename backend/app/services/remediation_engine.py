"""
Remediation Engine for TeamCode AI.
Provides Layer 2 deterministic and rule-based safe auto-fixes when LLM/Groq is unavailable,
rate-limited, or fails. Never invents unsafe code or unverified libraries.
"""
import ast
import re
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from app.models import FindingItem

logger = logging.getLogger("teamcode.remediation")


@dataclass
class RemediationResult:
    fixed_code: Optional[str]
    changes_made: List[str] = field(default_factory=list)
    remaining_risks: List[str] = field(default_factory=list)
    method: str = "deterministic"
    rule_ids_addressed: List[str] = field(default_factory=list)


def detect_database_driver_and_placeholder(code: str, context_hint: Optional[str] = None) -> Tuple[str, str]:
    """
    Detects the database driver and the correct parameter placeholder style.
    Returns (driver_name, placeholder).
    
    Examples:
    - sqlite3 -> ("sqlite3", "?")
    - psycopg / psycopg2 / postgres / postgresql -> ("postgresql", "%s")
    - mysql / pymysql / mysql.connector -> ("mysql", "%s")
    - cx_oracle / oracle -> ("oracle", ":val")
    - pyodbc / mssql -> ("mssql", "?")
    """
    combined = f"{code}\n{context_hint or ''}".lower()

    # 1. SQLite detection
    if "sqlite3" in combined or ".connect(" in combined and (".db" in combined or ".sqlite" in combined):
        return "sqlite3", "?"
    if "sqlite" in (context_hint or "").lower():
        return "sqlite3", "?"

    # 2. PostgreSQL detection
    if any(p in combined for p in ("psycopg2", "psycopg", "asyncpg", "postgres", "postgresql")):
        return "postgresql", "%s"
    if "postgres" in (context_hint or "").lower():
        return "postgresql", "%s"

    # 3. MySQL detection
    if any(m in combined for m in ("mysql", "pymysql", "mariadb")):
        return "mysql", "%s"

    # 4. Oracle detection
    if any(o in combined for o in ("cx_oracle", "oracledb")):
        return "oracle", ":val"

    # 5. Fallback based on code context
    if "sqlite" in combined:
        return "sqlite3", "?"
    
    # Default for Python DB-API if unstated: check standard imports
    if "import sqlite3" in code:
        return "sqlite3", "?"
    if "import psycopg2" in code or "import psycopg" in code:
        return "postgresql", "%s"

    # If neither, default to '?' (standard SQLite/DB-API parameter style)
    return "sqlite3", "?"


class RemediationEngine:
    """
    Deterministic rule-based code remediation engine.
    Applies well-tested, dialect-aware, safe transformations to eliminate known vulnerabilities.
    """

    def generate_remediation(
        self,
        original_code: str,
        language: str,
        findings: List[FindingItem],
        context_hint: Optional[str] = None,
    ) -> Optional[RemediationResult]:
        if not original_code or not original_code.strip() or not findings:
            return None

        lang_lower = (language or "python").lower()

        # Prioritize critical and high-severity security findings
        rule_ids = [f.rule_id for f in findings if f.requires_fix]
        if not rule_ids:
            return None

        current_code = original_code
        all_changes: List[str] = []
        all_risks: List[str] = []
        fixed_rules: List[str] = []

        # 1. Python Remediation
        if lang_lower in ("python", "py", "auto", "text"):
            # A. SQL Injection (SQL001)
            if "SQL001" in rule_ids:
                res = self._remediate_python_sql(current_code, context_hint)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SQL001")

            # B. Hardcoded Secrets (SEC001)
            if "SEC001" in rule_ids:
                res = self._remediate_python_secret(current_code, context_hint)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SEC001")

            # C. Command Injection (CMD001)
            if "CMD001" in rule_ids:
                res = self._remediate_python_command_injection(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("CMD001")

            # D. Dangerous eval/exec (SEC_EVAL)
            if "SEC_EVAL" in rule_ids:
                res = self._remediate_python_eval(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SEC_EVAL")

            # E. Insecure Deserialization (DES001)
            if "DES001" in rule_ids:
                res = self._remediate_python_deserialization(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("DES001")

            # F. Quality: Empty Exception Handler (QAL001)
            if "QAL001" in rule_ids:
                res = self._remediate_python_empty_except(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("QAL001")

        # 2. JavaScript / TypeScript Remediation
        elif lang_lower in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
            if "SEC_XSS" in rule_ids:
                res = self._remediate_js_xss(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SEC_XSS")

            if "SQL001" in rule_ids:
                res = self._remediate_js_sql(current_code, context_hint)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SQL001")

            if "SEC001" in rule_ids:
                res = self._remediate_js_secret(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SEC001")

        # 3. C / C++ Remediation
        elif lang_lower in ("c", "cpp", "c++", "h", "hpp"):
            if "MEM001" in rule_ids:
                res = self._remediate_c_buffer(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("MEM001")

        # 4. Java Remediation
        elif lang_lower in ("java",):
            if "SQL001" in rule_ids:
                res = self._remediate_java_sql(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SQL001")

        # 5. Go Remediation
        elif lang_lower in ("go", "golang"):
            if "SQL001" in rule_ids:
                res = self._remediate_go_sql(current_code)
                if res:
                    current_code, changes, risks = res
                    all_changes.extend(changes)
                    all_risks.extend(risks)
                    fixed_rules.append("SQL001")

        if current_code != original_code and fixed_rules:
            return RemediationResult(
                fixed_code=current_code,
                changes_made=all_changes or ["Applied deterministic security remediation."],
                remaining_risks=all_risks,
                method="deterministic",
                rule_ids_addressed=fixed_rules,
            )

        return None

    # =========================================================================
    # PYTHON REMEDIATIONS
    # =========================================================================

    def _remediate_python_sql(
        self, code: str, context_hint: Optional[str] = None
    ) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates Python SQL injection by transforming f-strings, concatenation,
        and formatting into parameterized queries with driver-accurate placeholders (? vs %s).
        """
        driver_name, placeholder = detect_database_driver_and_placeholder(code, context_hint)
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        # Case 1: Separate query variable followed by cursor.execute(query)
        # e.g.:
        #   query = f"SELECT ... WHERE username = '{username}'"
        #   cursor.execute(query)
        # or
        #   query = "SELECT ... WHERE username = '" + username + "'"
        #   cursor.execute(query)

        query_var_name = None
        extracted_params: List[str] = []
        query_line_idx = -1

        for idx, line in enumerate(lines):
            # A. Look for query variable assignment
            assign_match = re.match(
                r"""^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*f(['"])(.*?)\3\s*$""", line
            )
            if assign_match:
                indent, var_name, quote, content = (
                    assign_match.group(1),
                    assign_match.group(2),
                    assign_match.group(3),
                    assign_match.group(4),
                )
                if any(k in content.upper() for k in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                    # Find all {param} in content
                    params = re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", content)
                    if params:
                        # Replace '{param}' or {param} with placeholder
                        new_content = re.sub(r"['\"]?\{[a-zA-Z_][a-zA-Z0-9_]*\}['\"]?", placeholder, content)
                        new_lines[idx] = f'{indent}{var_name} = "{new_content}"'
                        query_var_name = var_name
                        extracted_params = params
                        query_line_idx = idx
                        modified = True
                        changes.append(
                            f"Replaced string interpolation in SQL query '{var_name}' with '{placeholder}' placeholder for {driver_name}."
                        )
                        continue

            # B. Look for string concatenation query assignment
            # e.g.: query = "SELECT * FROM users WHERE username = '" + username + "'"
            concat_match = re.match(
                r"""^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"](.*?SELECT.*?WHERE.*?)['"]\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)(.*)$""",
                line,
                re.IGNORECASE,
            )
            if concat_match:
                indent, var_name, prefix, param, remainder = (
                    concat_match.group(1),
                    concat_match.group(2),
                    concat_match.group(3),
                    concat_match.group(4),
                    concat_match.group(5),
                )
                # Clean trailing quotes from prefix (e.g. username = ')
                clean_prefix = re.sub(r"['\"]?\s*$", "", prefix)
                new_lines[idx] = f'{indent}{var_name} = "{clean_prefix} {placeholder}"'
                query_var_name = var_name
                extracted_params = [param]
                query_line_idx = idx
                modified = True
                changes.append(
                    f"Replaced string concatenation in SQL query '{var_name}' with '{placeholder}' placeholder for {driver_name}."
                )
                continue

            # C. Look for % formatting query assignment
            # e.g.: query = "SELECT * FROM users WHERE username = '%s'" % (username,)
            mod_match = re.match(
                r"""^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"](.*?SELECT.*?WHERE.*?)['"]\s*%\s*(?:\(?([a-zA-Z_][a-zA-Z0-9_,\s]*)\)?)\s*$""",
                line,
                re.IGNORECASE,
            )
            if mod_match:
                indent, var_name, content, raw_params = (
                    mod_match.group(1),
                    mod_match.group(2),
                    mod_match.group(3),
                    mod_match.group(4),
                )
                params = [p.strip() for p in raw_params.split(",") if p.strip()]
                clean_content = re.sub(r"['\"]?%s['\"]?", placeholder, content)
                new_lines[idx] = f'{indent}{var_name} = "{clean_content}"'
                query_var_name = var_name
                extracted_params = params
                query_line_idx = idx
                modified = True
                changes.append(
                    f"Replaced '%' formatting in SQL query '{var_name}' with parameterized '{placeholder}' placeholder for {driver_name}."
                )
                continue

            # D. Look for direct cursor.execute with f-string
            # e.g.: cursor.execute(f"SELECT ... {username}")
            direct_exec_match = re.match(
                r"""^(\s*)([a-zA-Z0-9_.]+)\.execute\(\s*f(['"])(.*?)\3\s*\)\s*$""", line
            )
            if direct_exec_match:
                indent, exec_obj, quote, content = (
                    direct_exec_match.group(1),
                    direct_exec_match.group(2),
                    direct_exec_match.group(3),
                    direct_exec_match.group(4),
                )
                if any(k in content.upper() for k in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                    params = re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", content)
                    if params:
                        new_content = re.sub(r"['\"]?\{[a-zA-Z_][a-zA-Z0-9_]*\}['\"]?", placeholder, content)
                        param_tuple_str = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
                        new_lines[idx] = f'{indent}{exec_obj}.execute("{new_content}", {param_tuple_str})'
                        modified = True
                        changes.append(
                            f"Parameterized direct '{exec_obj}.execute' call using '{placeholder}' placeholder and parameter tuple."
                        )
                        continue

        # If a query variable was modified, update subsequent cursor.execute(query) to pass params
        if query_var_name and extracted_params and query_line_idx >= 0:
            for idx in range(query_line_idx + 1, len(lines)):
                exec_match = re.match(
                    rf"""^(\s*)([a-zA-Z0-9_.]+)\.execute\(\s*{re.escape(query_var_name)}\s*\)\s*$""",
                    new_lines[idx],
                )
                if exec_match:
                    indent, exec_obj = exec_match.group(1), exec_match.group(2)
                    param_tuple_str = (
                        f"({extracted_params[0]},)"
                        if len(extracted_params) == 1
                        else f"({', '.join(extracted_params)})"
                    )
                    new_lines[idx] = f"{indent}{exec_obj}.execute({query_var_name}, {param_tuple_str})"
                    changes.append(
                        f"Updated '{exec_obj}.execute({query_var_name})' to pass parameters securely: ({', '.join(extracted_params)})."
                    )
                    break

        if modified:
            fixed_code = "\n".join(new_lines)
            return fixed_code, changes, []

        return None

    def _remediate_python_secret(
        self, code: str, context_hint: Optional[str] = None
    ) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates hardcoded secrets by extracting credentials into os.getenv(<ENV_VAR>).
        Ensures `import os` is present and never exposes the raw secret.
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        secret_pattern = re.compile(
            r"""^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,})['"]\s*(#.*)?$"""
        )

        for idx, line in enumerate(lines):
            match = secret_pattern.match(line)
            if match:
                indent, var_name, secret_val, comment = (
                    match.group(1),
                    match.group(2),
                    match.group(3),
                    match.group(4) or "",
                )
                var_lower = var_name.lower()
                # Check if this variable is a credential
                if any(
                    k in var_lower
                    for k in (
                        "api_key", "secret", "password", "passwd", "token",
                        "auth_token", "access_key", "private_key", "jwt"
                    )
                ):
                    # Derive contextual env var name
                    if "db" in var_lower or "database" in var_lower:
                        env_var = "DB_PASSWORD" if "pass" in var_lower else "DB_API_KEY"
                    elif "password" in var_lower or "passwd" in var_lower:
                        env_var = "DB_PASSWORD" if "db" in (context_hint or "").lower() else "APP_PASSWORD"
                    elif "jwt" in var_lower:
                        env_var = "JWT_SECRET_KEY"
                    elif "token" in var_lower:
                        env_var = "AUTH_TOKEN"
                    else:
                        env_var = var_name.upper()

                    new_lines[idx] = f'{indent}{var_name} = os.getenv("{env_var}", ""){f" {comment}" if comment else ""}'
                    modified = True
                    changes.append(
                        f"Extracted hardcoded secret assigned to '{var_name}' into environment variable os.getenv('{env_var}')."
                    )

        if modified:
            fixed_code = "\n".join(new_lines)
            # Ensure `import os` is present
            if not re.search(r"""(?m)^\s*import\s+os\b|^\s*from\s+os\b""", fixed_code):
                fixed_code = "import os\n" + fixed_code
                changes.insert(0, "Added 'import os' to load credentials securely from environment.")
            return fixed_code, changes, ["Configure the environment variable outside source control (.env or secret store)."]

        return None

    def _remediate_python_command_injection(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates command injection by converting dangerous shell commands to subprocess.run(..., shell=False).
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        for idx, line in enumerate(lines):
            # A. os.system(f"cmd {arg}") or os.system("cmd " + arg)
            os_sys_match = re.match(r"""^(\s*)os\.system\(\s*f['"](.*?)\{(.*?)\}(.*?)['"]\s*\)\s*$""", line)
            if os_sys_match:
                indent, prefix, var, suffix = os_sys_match.group(1), os_sys_match.group(2).strip(), os_sys_match.group(3).strip(), os_sys_match.group(4).strip()
                cmd_tokens = prefix.split()
                args_list_str = str(cmd_tokens + [var] + (suffix.split() if suffix else []))
                # clean up quotes in representation
                clean_args = ", ".join([f'"{tok}"' if tok not in (var,) else var for tok in (cmd_tokens + [var] + suffix.split())])
                new_lines[idx] = f"{indent}subprocess.run([{clean_args}], shell=False, check=True)"
                modified = True
                changes.append(f"Replaced dangerous 'os.system' with safe 'subprocess.run' using argument list and shell=False.")
                continue

            # B. subprocess.run(..., shell=True)
            if "shell=True" in line and "subprocess." in line:
                new_line = re.sub(r"""\bshell\s*=\s*True\b""", "shell=False", line)
                new_lines[idx] = new_line
                modified = True
                changes.append("Eliminated shell=True to prevent shell command injection.")
                continue

        if modified:
            fixed_code = "\n".join(new_lines)
            if not re.search(r"""(?m)^\s*import\s+subprocess\b""", fixed_code):
                fixed_code = "import subprocess\n" + fixed_code
                changes.insert(0, "Added 'import subprocess' for secure command execution.")
            return fixed_code, changes, []

        return None

    def _remediate_python_eval(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces unsafe eval() with safe ast.literal_eval().
        """
        if "eval(" not in code:
            return None

        # Replace eval(x) with ast.literal_eval(x)
        new_code = re.sub(r"""\beval\s*\(""", "ast.literal_eval(", code)
        if new_code != code:
            changes = ["Replaced arbitrary code execution eval() with safe ast.literal_eval()."]
            if not re.search(r"""(?m)^\s*import\s+ast\b""", new_code):
                new_code = "import ast\n" + new_code
                changes.insert(0, "Added 'import ast' for safe expression evaluation.")
            return new_code, changes, []

        return None

    def _remediate_python_deserialization(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces unsafe pickle.loads with safe json.loads.
        """
        if "pickle." not in code:
            return None

        new_code = re.sub(r"""\bpickle\.(?:loads|load)\b""", "json.loads", code)
        if new_code != code:
            changes = ["Replaced insecure Python pickle deserialization with safe json.loads()."]
            if not re.search(r"""(?m)^\s*import\s+json\b""", new_code):
                new_code = "import json\n" + new_code
                changes.insert(0, "Added 'import json' for secure data serialization.")
            return new_code, changes, []

        return None

    def _remediate_python_empty_except(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces bare 'except: pass' or 'except Exception: pass' with logging/handling.
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        for idx, line in enumerate(lines[:-1]):
            if re.match(r"""^\s*except(?:\s+Exception)?\s*:\s*$""", line):
                next_line = lines[idx + 1]
                pass_match = re.match(r"""^(\s*)pass\s*$""", next_line)
                if pass_match:
                    indent = pass_match.group(1)
                    new_lines[idx] = re.sub(r""":\s*$""", " as err:", line)
                    new_lines[idx + 1] = f'{indent}# Log and handle error instead of silent swallowing\n{indent}print(f"Handled exception: {{err}}")'
                    modified = True
                    changes.append("Replaced silent empty exception block with error logging.")

        if modified:
            return "\n".join(new_lines), changes, []

        return None

    # =========================================================================
    # JAVASCRIPT / TYPESCRIPT REMEDIATIONS
    # =========================================================================

    def _remediate_js_xss(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces element.innerHTML = x with element.textContent = x.
        """
        if ".innerHTML" not in code:
            return None

        new_code = re.sub(r"""\.innerHTML\s*=""", ".textContent =", code)
        if new_code != code:
            return new_code, ["Replaced unescaped '.innerHTML' assignment with safe '.textContent' to prevent XSS."], []

        return None

    def _remediate_js_sql(self, code: str, context_hint: Optional[str] = None) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces JavaScript/TypeScript template literal SQL interpolation with parameterized queries.
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        for idx, line in enumerate(lines):
            # Match query = `SELECT ... ${var}`
            tpl_match = re.match(r"""^(\s*)(const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*`([^`]*SELECT[^`]*)`\s*;?\s*$""", line, re.IGNORECASE)
            if tpl_match:
                indent, kw, var_name, content = tpl_match.group(1), tpl_match.group(2), tpl_match.group(3), tpl_match.group(4)
                params = re.findall(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}", content)
                if params:
                    # Replace ${param} with $1, $2 (Postgres/node-pg) or ?
                    use_dollar = "postgres" in (context_hint or "").lower() or "$1" in code or "pg" in code
                    clean_content = content
                    for pIdx, p in enumerate(params, 1):
                        ph = f"${pIdx}" if use_dollar else "?"
                        clean_content = clean_content.replace(f"${{{p}}}", ph)

                    new_lines[idx] = f'{indent}{kw} {var_name} = "{clean_content}";'
                    modified = True
                    changes.append(f"Parameterized SQL template query '{var_name}' using placeholders instead of template string interpolation.")

        if modified:
            return "\n".join(new_lines), changes, []

        return None

    def _remediate_js_secret(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Replaces hardcoded API keys in JS/TS with process.env.<ENV_VAR>.
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        secret_pattern = re.compile(
            r"""^(\s*)(const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*['"]([a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,})['"]\s*;?\s*$"""
        )

        for idx, line in enumerate(lines):
            match = secret_pattern.match(line)
            if match:
                indent, kw, var_name = match.group(1), match.group(2), match.group(3)
                var_lower = var_name.lower()
                if any(k in var_lower for k in ("api_key", "secret", "password", "token")):
                    env_var = var_name.upper()
                    new_lines[idx] = f'{indent}{kw} {var_name} = process.env.{env_var} || "";'
                    modified = True
                    changes.append(f"Loaded '{var_name}' from process.env.{env_var} instead of hardcoding in source.")

        if modified:
            return "\n".join(new_lines), changes, ["Configure environment variable in .env or hosting environment."]

        return None

    # =========================================================================
    # C / C++ REMEDIATIONS
    # =========================================================================

    def _remediate_c_buffer(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates unbounded C buffer functions:
        gets(buf) -> fgets(buf, sizeof(buf), stdin)
        """
        lines = code.split("\n")
        new_lines = list(lines)
        modified = False
        changes = []

        for idx, line in enumerate(lines):
            gets_match = re.match(r"""^(\s*)gets\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*;?\s*$""", line)
            if gets_match:
                indent, buf_name = gets_match.group(1), gets_match.group(2)
                new_lines[idx] = f"{indent}fgets({buf_name}, sizeof({buf_name}), stdin);"
                modified = True
                changes.append(f"Replaced dangerous unbounded 'gets({buf_name})' with safe 'fgets({buf_name}, sizeof({buf_name}), stdin)'.")

        if modified:
            return "\n".join(new_lines), changes, []

        return None

    # =========================================================================
    # JAVA REMEDIATIONS
    # =========================================================================

    def _remediate_java_sql(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates Java Statement.executeQuery string concatenation with PreparedStatement.
        """
        if "Statement.executeQuery" in code or ".executeQuery(" in code:
            # Replace stmt.executeQuery("SELECT ... " + id)
            match = re.search(r"""([a-zA-Z_][a-zA-Z0-9_]*)\.executeQuery\(\s*['"](.*?SELECT.*?WHERE.*?)['"]\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)""", code, re.IGNORECASE)
            if match:
                stmt_var, query_prefix, param = match.group(1), match.group(2), match.group(3)
                safe_block = (
                    f'PreparedStatement pstmt = conn.prepareStatement("{query_prefix} ?");\n'
                    f'    pstmt.setString(1, {param});\n'
                    f'    ResultSet rs = pstmt.executeQuery()'
                )
                new_code = code.replace(match.group(0), safe_block)
                return new_code, ["Replaced statement string concatenation with parameterized PreparedStatement."], []

        return None

    # =========================================================================
    # GO REMEDIATIONS
    # =========================================================================

    def _remediate_go_sql(self, code: str) -> Optional[Tuple[str, List[str], List[str]]]:
        """
        Remediates Go db.Query(fmt.Sprintf("SELECT ... %s", id)) with db.Query("SELECT ... $1", id) or db.Query("SELECT ... ?", id).
        """
        match = re.search(r"""([a-zA-Z_][a-zA-Z0-9_]*)\.Query(?:Row)?\(\s*fmt\.Sprintf\(\s*['"](.*?SELECT.*?WHERE.*?)%[svd]['"]\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*\)""", code, re.IGNORECASE)
        if match:
            db_var, query_prefix, param = match.group(1), match.group(2), match.group(3)
            safe_call = f'{db_var}.Query("{query_prefix} $1", {param})'
            new_code = code.replace(match.group(0), safe_call)
            return new_code, [f"Replaced fmt.Sprintf SQL query with parameterized placeholder call: {db_var}.Query(..., {param})."], []

        return None


remediation_engine = RemediationEngine()
