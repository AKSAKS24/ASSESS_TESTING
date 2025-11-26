# backend/app.py
import os
import json
import base64
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import quote

import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# optional LLM client import (kept optional)
try:
    from langchain_openai import ChatOpenAI
except Exception:
    ChatOpenAI = None

# load .env
load_dotenv()

# ---------- basic logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sap-finstat-api")

# -------------------- CONFIG from env --------------------
SAP_USERNAME = os.getenv("SAP_USERNAME")
SAP_PASSWORD = os.getenv("SAP_PASSWORD")
SAP_BASE_URL = os.getenv("SAP_BASE_URL")  # e.g. https://s4hananewtds.pwcglb.com:44300
SAP_ODATA_BASEPATH = os.getenv(
    "SAP_ODATA_BASEPATH",
    "/sap/opu/odata/sap/FAC_FINANCIAL_STATEMENT_SRV/FinStmntSet",
)  # default to FinStmntSet path
SAP_CLIENT = os.getenv("SAP_CLIENT", "100")

if not SAP_USERNAME or not SAP_PASSWORD or not SAP_BASE_URL:
    raise RuntimeError("Missing SAP_USERNAME / SAP_PASSWORD / SAP_BASE_URL in environment")

# Basic auth header
_auth_bytes = f"{SAP_USERNAME}:{SAP_PASSWORD}".encode("utf-8")
_auth_b64 = base64.b64encode(_auth_bytes).decode("utf-8")

# Reusable requests session
session = requests.Session()
session.headers.update({
    "Authorization": f"Basic {_auth_b64}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() in ("1", "true", "yes")
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "60"))

# optional LLM config
LLM_ENABLED = False
if ChatOpenAI is not None and os.getenv("OPENAI_API_KEY"):
    try:
        llm = ChatOpenAI(
            model=os.getenv("LLM_MODEL", "bedrock.anthropic.claude-opus-4"),
            temperature=0,
            base_url=os.getenv("LLM_BASE_URL", "https://genai-sharedservice-americas.pwcinternal.com"),
            api_key=os.getenv("OPENAI_API_KEY"),
        )
        LLM_ENABLED = True
    except Exception as e:
        logger.warning("LLM init failed (will use fallback): %s", e)
        LLM_ENABLED = False

# -------------------- FASTAPI --------------------
app = FastAPI(title="SAP Financial Statements API (env-driven)")

# Dev CORS: allow all. Restrict in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------- HELPERS --------------------
def _enc(val: Optional[str]) -> str:
    """
    Wrap value in %27...%27 (URL-encoded single quotes).
    Empty/None becomes %27%27.
    """
    if val is None or val == "":
        return "%27%27"
    s = str(val)
    return f"%27{quote(s)}%27"


def sap_yearperiod(year: Optional[str], month: Optional[str]) -> Optional[str]:
    if not year or not month:
        return None
    try:
        y = str(year)
        m = int(month)
        if m < 1 or m > 12:
            return None
        # SAP format: YYYY + 3-digit month-index e.g. 2025001
        return f"{y}{str(m).zfill(3)}"
    except Exception:
        return None


def build_odata_url(
    *,
    P_KTOPL: Optional[str] = None,
    P_VERSN: Optional[str] = None,
    P_BILABTYP: Optional[str] = None,
    P_XKTOP2: Optional[str] = None,
    P_COMP_YEAR: Optional[str] = None,
    P_YEAR: Optional[str] = None,
    P_BUKRS: Optional[str] = None,
    P_RLDNR: Optional[str] = None,
    P_CURTP: Optional[str] = None,
    P_FROM_YEARPERIOD: Optional[str] = None,
    P_TO_YEARPERIOD: Optional[str] = None,
    P_FROM_COMPYEARPERIOD: Optional[str] = None,
    P_TO_COMPYEARPERIOD: Optional[str] = None,
    # filter parameters (will be put in $filter with %27 quoting)
    filter_company_code: Optional[str] = None,
    filter_ledger: Optional[str] = None,
    filter_financial_statement_variant: Optional[str] = None,
    sap_client: str = SAP_CLIENT,
) -> str:
    # defaults (can all be overridden by user)
    P_KTOPL = P_KTOPL or "0808"
    P_VERSN = P_VERSN or "2000_DRAFT"
    P_BILABTYP = P_BILABTYP or "1"
    P_XKTOP2 = P_XKTOP2 or ""
    P_COMP_YEAR = P_COMP_YEAR or ""
    P_YEAR = P_YEAR or ""
    P_BUKRS = P_BUKRS or P_KTOPL
    P_RLDNR = P_RLDNR or "0L"
    P_CURTP = P_CURTP or "10"
    P_FROM_YEARPERIOD = P_FROM_YEARPERIOD or ""
    P_TO_YEARPERIOD = P_TO_YEARPERIOD or P_FROM_YEARPERIOD
    P_FROM_COMPYEARPERIOD = P_FROM_COMPYEARPERIOD or ""
    P_TO_COMPYEARPERIOD = P_TO_COMPYEARPERIOD or P_FROM_COMPYEARPERIOD

    parts = {
        "P_KTOPL": P_KTOPL,
        "P_VERSN": P_VERSN,
        "P_BILABTYP": P_BILABTYP,
        "P_XKTOP2": P_XKTOP2,
        "P_COMP_YEAR": P_COMP_YEAR,
        "P_YEAR": P_YEAR,
        "P_BUKRS": P_BUKRS,
        "P_RLDNR": P_RLDNR,
        "P_CURTP": P_CURTP,
        "P_FROM_YEARPERIOD": P_FROM_YEARPERIOD,
        "P_TO_YEARPERIOD": P_TO_YEARPERIOD,
        "P_FROM_COMPYEARPERIOD": P_FROM_COMPYEARPERIOD,
        "P_TO_COMPYEARPERIOD": P_TO_COMPYEARPERIOD,
        "P_ZERO": "",
    }

    ident_pairs = ",".join(f"{k}={_enc(v)}" for k, v in parts.items())
    ident_segment = f"({ident_pairs})/Result"

    select_clause = (
        "$select=FinancialStatementVariant,FinancialStatementItem,FinancialStatementItemText,"
        "Currency,Ledger,HierarchyNode,OperativeGLAccount,OperativeGLAccountName,FinStatementHierarchyLevelVal,"
        "ParentNode,ChildNode,NodeType,ReportingPeriodAmount,ComparisonPeriodAmount,RelativeDifferencePercent,"
        "AbsoluteDifferenceAmount,CorporateGroupAccount,CorporateGroupAccountName,PlanningCategory,FunctionalArea"
    )

    extra = "&$top=1000000&$orderby=HierarchyNode,FinStatementHierarchyLevelVal,FinancialStatementItem,OperativeGLAccount asc"

    # ---- $filter construction with %27 quoting ----
    filter_clause = ""
    filter_parts = []

    if filter_company_code:
        # CompanyCode eq '%27value%27'
        filter_parts.append(f"CompanyCode%20eq%20{_enc(filter_company_code)}")

    if filter_ledger:
        # Ledger eq '%27value%27'
        filter_parts.append(f"Ledger%20eq%20{_enc(filter_ledger)}")

    if filter_financial_statement_variant:
        # FinancialStatementVariant eq '%27value%27'
        filter_parts.append(f"FinancialStatementVariant%20eq%20{_enc(filter_financial_statement_variant)}")

    if filter_parts:
        filter_expr = "%20and%20".join(filter_parts)
        filter_clause = f"&$filter=({filter_expr})"

    url = (
        f"{SAP_BASE_URL}{SAP_ODATA_BASEPATH}{ident_segment}"
        f"?sap-client={sap_client}&{select_clause}{extra}{filter_clause}"
    )
    return url


def fetch_financial_statements(url: str) -> List[Dict[str, Any]]:
    logger.info("Fetching SAP OData URL: %s", url)
    headers = {"X-CSRF-Token": "Fetch"}
    resp = session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
    if resp.status_code != 200:
        logger.error("SAP responded %s: %s", resp.status_code, resp.text[:400])
        raise HTTPException(status_code=500, detail=f"SAP error: {resp.status_code} {resp.text[:400]}")
    try:
        data = resp.json()
    except Exception as e:
        logger.exception("Invalid JSON from SAP")
        raise HTTPException(status_code=500, detail=f"Invalid JSON from SAP: {e}")
    results = data.get("d", {}).get("results", [])
    if not isinstance(results, list):
        logger.error("Unexpected SAP response structure: %s", data)
        raise HTTPException(status_code=500, detail="Unexpected SAP response structure (missing d.results list)")
    return results


def build_tree_with_children(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for r in records:
        if "Children" not in r:
            r["Children"] = []
    by_id = {str(r.get("HierarchyNode")): r for r in records if r.get("HierarchyNode") is not None}
    roots: List[Dict[str, Any]] = []
    for r in records:
        parent = r.get("ParentNode")
        if parent and str(parent) in by_id:
            by_id[str(parent)]["Children"].append(r)
        else:
            roots.append(r)
    return roots


# -------------------- Pydantic models --------------------
class SummarizeRequest(BaseModel):
    scope: str
    nodes: list


# -------------------- ROUTES --------------------
@app.get("/financial-statements")
def financial_statements(
    P_KTOPL: Optional[str] = Query(None),
    P_VERSN: Optional[str] = Query(None),
    P_BILABTYP: Optional[str] = Query(None),
    P_XKTOP2: Optional[str] = Query(None),
    P_COMP_YEAR: Optional[str] = Query(None),
    P_YEAR: Optional[str] = Query(None),
    P_BUKRS: Optional[str] = Query(None),
    P_RLDNR: Optional[str] = Query(None),
    P_CURTP: Optional[str] = Query(None),
    P_FROM_YEARPERIOD: Optional[str] = Query(None),
    P_TO_YEARPERIOD: Optional[str] = Query(None),
    P_FROM_COMPYEARPERIOD: Optional[str] = Query(None),
    P_TO_COMPYEARPERIOD: Optional[str] = Query(None),
    endYear: Optional[str] = Query(None),
    endMonth: Optional[str] = Query(None),
    compYear: Optional[str] = Query(None),
    compMonth: Optional[str] = Query(None),
    # filter values from user input (all dynamic)
    CompanyCode: Optional[str] = Query(None),
    Ledger: Optional[str] = Query(None),
    FinancialStatementVariant: Optional[str] = Query(None),
    sap_client: str = Query(SAP_CLIENT),
):
    # Optionally compute single-yearperiod from (endYear, endMonth)
    if endYear or endMonth:
        computed = sap_yearperiod(endYear, endMonth)
        if computed is None:
            raise HTTPException(status_code=400, detail="Invalid endYear/endMonth (month must be 1-12).")
        if not P_FROM_YEARPERIOD:
            P_FROM_YEARPERIOD = computed
        if not P_TO_YEARPERIOD:
            P_TO_YEARPERIOD = computed
        P_YEAR = endYear or P_YEAR

    # Optionally compute comparison yearperiod
    if compYear or compMonth:
        computed_comp = sap_yearperiod(compYear, compMonth)
        if computed_comp is None:
            raise HTTPException(status_code=400, detail="Invalid compYear/compMonth (month must be 1-12).")
        if not P_FROM_COMPYEARPERIOD:
            P_FROM_COMPYEARPERIOD = computed_comp
        if not P_TO_COMPYEARPERIOD:
            P_TO_COMPYEARPERIOD = computed_comp
        P_COMP_YEAR = compYear or P_COMP_YEAR

    try:
        odata_url = build_odata_url(
            P_KTOPL=P_KTOPL,
            P_VERSN=P_VERSN,
            P_BILABTYP=P_BILABTYP,
            P_XKTOP2=P_XKTOP2,
            P_COMP_YEAR=P_COMP_YEAR,
            P_YEAR=P_YEAR,
            P_BUKRS=P_BUKRS,
            P_RLDNR=P_RLDNR,
            P_CURTP=P_CURTP,
            P_FROM_YEARPERIOD=P_FROM_YEARPERIOD,
            P_TO_YEARPERIOD=P_TO_YEARPERIOD,
            P_FROM_COMPYEARPERIOD=P_FROM_COMPYEARPERIOD,
            P_TO_COMPYEARPERIOD=P_TO_COMPYEARPERIOD,
            # build $filter dynamically; fall back to P_ values if explicit filter inputs not given
            filter_company_code=CompanyCode or P_BUKRS,
            filter_ledger=Ledger or P_RLDNR,
            filter_financial_statement_variant=FinancialStatementVariant or P_VERSN,
            sap_client=sap_client,
        )
        logger.info("Final OData URL built: %s", odata_url)
    except Exception as e:
        logger.exception("Failed to build URL")
        raise HTTPException(status_code=500, detail=f"Failed to build OData URL: {e}")

    records = fetch_financial_statements(odata_url)
    tree = build_tree_with_children(records)
    return {"records": tree, "odata_url": odata_url}


@app.post("/summarize_tree")
def summarize_tree(body: SummarizeRequest):
    nodes_preview = body.nodes[:50]
    prompt = (
        "You are an assistant summarizing SAP Financial Statement hierarchies.\n"
        "User has selected the following scope and nodes from a tree view.\n\n"
        f"Scope: {body.scope}\n\n"
        "Nodes JSON:\n"
        f"{json.dumps(nodes_preview, indent=2)}\n\n"
        "Summarize the key financial insights (major items, directions, and any obvious patterns). "
        "Use short, clear bullet points."
    )

    if not LLM_ENABLED:
        local_summary = "LLM not configured. Preview of nodes:\n"
        local_summary += "\n".join(
            [f"- {n.get('FinancialStatementItem','<item>')} ({n.get('HierarchyNode')})"
             for n in nodes_preview[:10]]
        )
        return {"summary": local_summary}

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        summary_text = getattr(response, "content", None) or (
            response[0].get("content") if isinstance(response, list) and response else str(response)
        )
    except Exception as e:
        logger.exception("LLM call failed")
        raise HTTPException(status_code=500, detail=f"LLM call failed: {str(e)}")

    return {"summary": summary_text}
