from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import re

# ---------------------------------------------------------------------
# APP INIT
# ---------------------------------------------------------------------
app = FastAPI(title="Legacy Table Scanner (Header + Findings Version)")


# ---------------------------------------------------------------------
# LOAD DYNAMIC MAPPING (tables.json)
# ---------------------------------------------------------------------
MAPPING_PATH = Path(__file__).parent / "tables.json"

with open(MAPPING_PATH, "r", encoding="utf-8") as f:
    TABLE_MAP: Dict[str, str] = json.load(f)

OLD_TABLES = list(TABLE_MAP.keys())

# Build dynamic regex-safe table list
TBL_GROUP = "|".join(sorted(map(re.escape, OLD_TABLES), key=len, reverse=True))


# ---------------------------------------------------------------------
# REGEX DEFINITIONS
# ---------------------------------------------------------------------
REGEX: Dict[str, re.Pattern] = {
    "DML": re.compile(
        rf"(?P<full>(?P<stmt>\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMODIFY\b)"
        rf"[\s\S]*?\b(FROM|INTO|UPDATE|DELETE\s+FROM)\b\s+(?P<obj>{TBL_GROUP})\b)",
        re.IGNORECASE,
    ),
    "CLEAR": re.compile(
        rf"(?P<full>\bCLEAR\b\s+(?P<obj>{TBL_GROUP})\b[\w\-]*)",
        re.IGNORECASE,
    ),
    "ASSIGN": re.compile(
        rf"(?P<full>((?P<obj>{TBL_GROUP})[\w\-]*\s*=\s*[\w\-\>]+"
        rf"|[\w\-\>]+\s*=\s*(?P<obj2>{TBL_GROUP})[\w\-]*))",
        re.IGNORECASE,
    ),
    "GENERIC": re.compile(
        rf"(?P<full>\b(?P<obj>{TBL_GROUP})\b)",
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------
# RESPONSE MODELS (Finding renamed as requested)
# ---------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None   # "DirectRead" | "DisallowedWrite"
    severity: Optional[str] = None      # "info" | "warning" | "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None       # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------
# HELPER: GET FULL LINE SNIPPET FOR A MATCH
# ---------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


# ---------------------------------------------------------------------
# HELPER: CLASSIFY ISSUE (issue_type, severity, message, suggestion)
# ---------------------------------------------------------------------
def classify_issue(
    pattern_name: str,
    stmt: Optional[str],
    table_name: str,
    replacement: Optional[str],
) -> Dict[str, str]:
    stmt_upper = (stmt or "").upper()

    # Determine issue type & severity
    if pattern_name == "DML":
        if stmt_upper == "SELECT":
            issue_type = "DirectRead"
            severity = "warning"
        else:
            # INSERT / UPDATE / DELETE / MODIFY
            issue_type = "DisallowedWrite"
            severity = "error"
    else:
        # CLEAR, ASSIGN, GENERIC – treat as read-like access
        issue_type = "DirectRead"
        severity = "info"

    # Message & suggestion
    if replacement:
        message = f"Legacy table {table_name} is used in a {pattern_name} statement."
        suggestion = f"Use {replacement} instead of {table_name}."
    else:
        message = f"Legacy table {table_name} is used but no replacement mapping is defined."
        suggestion = (
            "Add an entry in tables.json for this table or refactor to a supported object."
        )

    return {
        "issue_type": issue_type,
        "severity": severity,
        "message": message,
        "suggestion": suggestion,
    }


# ---------------------------------------------------------------------
# CORE SCANNER: FIND ALL TABLE USAGES IN A SINGLE CODE STRING
# ---------------------------------------------------------------------
def find_table_usage(txt: str) -> List[Dict[str, Any]]:
    """
    Runs all regexes over the given text and returns a list of matches.
    Each match contains:
      - pattern: which regex matched (DML / CLEAR / ASSIGN / GENERIC)
      - stmt: statement keyword (for DML)
      - object: table name
      - replacement_table: mapped new table (if any)
      - span: (start_char, end_char)
    """
    matches: List[Dict[str, Any]] = []
    seen = set()  # avoid duplicates (table, line_no, pattern)

    for pattern_name, pattern in REGEX.items():
        for m in pattern.finditer(txt or ""):
            gd = m.groupdict()
            obj = gd.get("obj") or gd.get("obj2")
            if not obj:
                continue

            start, end = m.span("full")

            # Dedup by (table_name, line number, pattern)
            line_no = txt[:start].count("\n") + 1
            key = (obj, line_no, pattern_name)
            if key in seen:
                continue
            seen.add(key)

            stmt = gd.get("stmt")
            replacement = TABLE_MAP.get(obj.upper())

            matches.append(
                {
                    "pattern": pattern_name,
                    "full": m.group("full"),
                    "stmt": stmt,
                    "object": obj,
                    "replacement_table": replacement,
                    "span": (start, end),
                }
            )

    matches.sort(key=lambda x: x["span"][0])
    return matches


# ---------------------------------------------------------------------
# API: /remediate-tables
#   - Request: List[Unit] (pgm_name, inc_name, type, name, start_line, end_line, code)
#   - Response: List[Unit] with findings populated (Finding using new field names)
# ---------------------------------------------------------------------
@app.post("/remediate-tables", response_model=List[Unit])
def remediate_tables(units: List[Unit]) -> List[Unit]:
    result_units: List[Unit] = []

    for u in units:
        src = u.code or ""
        base_start = u.start_line or 0  # block start line in program
        findings: List[Finding] = []

        for m in find_table_usage(src):
            start, end = m["span"]

            # Line within this block (1-based)
            line_in_block = src[:start].count("\n") + 1

            # Snippet = full line containing the match
            snippet_line = get_line_snippet(src, start, end)
            snippet_line_count = snippet_line.count("\n") + 1  # usually 1

            # Absolute line numbers in the full program
            start_line_abs = base_start + line_in_block
            end_line_abs = base_start + line_in_block + snippet_line_count

            # Classify issue
            table_name = m["object"]
            replacement = m["replacement_table"]
            stmt = m.get("stmt")
            issue_meta = classify_issue(
                pattern_name=m["pattern"],
                stmt=stmt,
                table_name=table_name,
                replacement=replacement,
            )

            finding = Finding(
                prog_name=u.pgm_name,
                incl_name=u.inc_name,
                types=u.type,
                blockname=u.name,
                starting_line=start_line_abs,
                ending_line=end_line_abs,
                issues_type=issue_meta["issue_type"],
                severity=issue_meta["severity"],
                message=issue_meta["message"],
                suggestion=issue_meta["suggestion"],
                snippet=snippet_line.replace("\n", "\\n"),
            )
            findings.append(finding)

        # Build response Unit: copy header and attach findings
        out_unit = Unit(**u.model_dump())
        out_unit.findings = findings
        result_units.append(out_unit)

    return result_units
