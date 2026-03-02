import os
import json
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware


BASE_DIR = Path(__file__).resolve().parent

def html_file(name: str) -> str:
    # Works whether files are in ./static or project root
    p1 = BASE_DIR / "static" / name
    p2 = BASE_DIR / name
    if p1.exists():
        return str(p1)
    if p2.exists():
        return str(p2)
    raise FileNotFoundError(f"Cannot find {name} in static/ or project root")


# ──────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────
app = FastAPI()

# ──────────────────────────────────────────────────────────────
# Settings (ENV)
# ──────────────────────────────────────────────────────────────
BASE_URL = os.getenv("BASE_URL", "").strip().rstrip("/")  # IMPORTANT: no trailing slash
PIPEDRIVE_CLIENT_ID = os.getenv("PIPEDRIVE_CLIENT_ID", "").strip()
PIPEDRIVE_CLIENT_SECRET = os.getenv("PIPEDRIVE_CLIENT_SECRET", "").strip()

UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip()
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()

STATIC_DIR = str(BASE_DIR / "static")
STATE_TTL_SECONDS = 600



def _missing_env(name: str) -> JSONResponse:
    """Return a clear JSON error instead of crashing the server."""
    return JSONResponse(
        {"error": f"Server misconfiguration: env var {name} is not set."},
        status_code=500,
    )


# ──────────────────────────────────────────────────────────────
# CORS
# ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.pipedrive.com"],
    allow_origin_regex=r"^https://.*\.pipedrive\.com$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────
# Iframe headers middleware
# ──────────────────────────────────────────────────────────────
class IframeHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)

        # Remove X-Frame-Options if present
        if "x-frame-options" in response.headers:
            del response.headers["x-frame-options"]

        # Allow embedding in Pipedrive
        response.headers["content-security-policy"] = (
            "frame-ancestors https://app.pipedrive.com https://*.pipedrive.com 'self'"
        )

        response.headers["referrer-policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(IframeHeadersMiddleware)


# ──────────────────────────────────────────────────────────────
# Upstash Redis helpers (optional) + in-memory fallback
# ──────────────────────────────────────────────────────────────
_mem_store: dict[str, str] = {}
_state_store: dict[str, int] = {}

def _redis(cmd: list):
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return None
    try:
        r = requests.post(
            UPSTASH_URL,
            headers={"Authorization": f"Bearer {UPSTASH_TOKEN}", "Content-Type": "application/json"},
            json=cmd,
            timeout=5,
        )
        if r.status_code != 200:
            return None
        return r.json().get("result")
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────
# Token storage
# ──────────────────────────────────────────────────────────────
def save_tokens(company_id: str, access_token: str, refresh_token: str, expires_in: int):
    expires_at = int(time.time()) + int(expires_in) - 60
    data = json.dumps(
        {"access_token": access_token, "refresh_token": refresh_token, "expires_at": expires_at}
    )
    key = f"oc:tokens:{company_id}"
    result = _redis(["SET", key, data, "EX", str(int(expires_in) + 86400)])
    if result is None:
        _mem_store[key] = data

def load_tokens(company_id: str):
    key = f"oc:tokens:{company_id}"
    raw = _redis(["GET", key])
    if raw is None:
        raw = _mem_store.get(key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

def save_oauth_state(state: str):
    key = f"oc:state:{state}"
    exp = int(time.time()) + STATE_TTL_SECONDS
    result = _redis(["SET", key, "1", "EX", str(STATE_TTL_SECONDS)])
    if result is None:
        _state_store[state] = exp

def consume_oauth_state(state: str) -> bool:
    key = f"oc:state:{state}"

    val = _redis(["GET", key])
    if val is not None:
        _redis(["DEL", key])
        return val == "1"

    exp = _state_store.pop(state, None)
    if exp is None:
        return False
    return int(time.time()) < exp


def refresh_access_token(company_id: str, refresh_token: str):
    if not PIPEDRIVE_CLIENT_ID or not PIPEDRIVE_CLIENT_SECRET:
        return None
    try:
        r = requests.post(
            "https://oauth.pipedrive.com/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": PIPEDRIVE_CLIENT_ID,
                "client_secret": PIPEDRIVE_CLIENT_SECRET,
            },
            timeout=15,
        )
        if r.status_code != 200:
            return None
        t = r.json()
        save_tokens(company_id, t["access_token"], t["refresh_token"], int(t.get("expires_in", 3600)))
        return t["access_token"]
    except Exception:
        return None


def get_valid_token(company_id: str):
    tokens = load_tokens(company_id)
    if not tokens:
        return None
    if int(time.time()) >= int(tokens.get("expires_at", 0)) - 300:
        return refresh_access_token(company_id, tokens.get("refresh_token", ""))
    return tokens.get("access_token")


# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return RedirectResponse("/panel")

@app.get("/panel")
def panel():
    return FileResponse(html_file("panel.html"))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/debug/context")
def debug_context(request: Request):
    return {
        "query": dict(request.query_params),
        "headers_subset": {
            "origin": request.headers.get("origin"),
            "referer": request.headers.get("referer"),
            "user-agent": request.headers.get("user-agent"),
        },
    }


# ──────────────────────────────────────────────────────────────
# OAuth
# ──────────────────────────────────────────────────────────────
@app.get("/oauth/start")
def oauth_start():
    if not BASE_URL:
        return _missing_env("BASE_URL")
    if not PIPEDRIVE_CLIENT_ID:
        return _missing_env("PIPEDRIVE_CLIENT_ID")

    redirect_uri = f"{BASE_URL}/oauth/callback"
    state = secrets.token_urlsafe(32)
    save_oauth_state(state)

    params = urlencode({
        "client_id": PIPEDRIVE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
    })

    return RedirectResponse(f"https://oauth.pipedrive.com/oauth/authorize?{params}")


@app.get("/oauth/callback")
def oauth_callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not state or not consume_oauth_state(state):
        return JSONResponse({"error": "Invalid or expired state."}, status_code=400)
    if not code:
        return JSONResponse({"error": "No authorisation code returned."}, status_code=400)

    if not BASE_URL:
        return _missing_env("BASE_URL")
    if not PIPEDRIVE_CLIENT_ID:
        return _missing_env("PIPEDRIVE_CLIENT_ID")
    if not PIPEDRIVE_CLIENT_SECRET:
        return _missing_env("PIPEDRIVE_CLIENT_SECRET")

    redirect_uri = f"{BASE_URL}/oauth/callback"

    r = requests.post(
        "https://oauth.pipedrive.com/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": PIPEDRIVE_CLIENT_ID,
            "client_secret": PIPEDRIVE_CLIENT_SECRET,
        },
        timeout=30,
    )
    if r.status_code != 200:
        return JSONResponse({"error": "Token exchange failed", "body": r.text}, status_code=400)

    tokens = r.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    expires_in = int(tokens.get("expires_in", 3600))

    me = requests.get(
        "https://api.pipedrive.com/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    me.raise_for_status()
    company_id = str(me.json()["data"]["company_id"])

    save_tokens(company_id, access_token, refresh_token, expires_in)
    return FileResponse(html_file("oauth_success.html"))


@app.get("/api/status")
def api_status(companyId: str = ""):
    if not companyId:
        return {"connected": False}
    return {"connected": bool(get_valid_token(companyId))}


# ──────────────────────────────────────────────────────────────
# Chart storage helpers  (Redis-first, in-memory fallback)
# ──────────────────────────────────────────────────────────────
# Key pattern:  oc:chart:{company_id}:{org_id}
# Value:        JSON string  {"chartName": "...", "chart": "...{nodes/edges JSON}..."}
# No TTL — chart data is permanent until explicitly overwritten.

def _chart_key(company_id: str, org_id: str) -> str:
    return f"oc:chart:{company_id}:{org_id}"


def save_chart_data(company_id: str, org_id: str, chart_name: str, chart_json: str) -> bool:
    key = _chart_key(company_id, org_id)
    value = json.dumps({"chartName": chart_name, "chart": chart_json})
    result = _redis(["SET", key, value])
    if result is None:
        # Redis not configured — fall back to in-memory store
        _mem_store[key] = value
    return True


def load_chart_data(company_id: str, org_id: str) -> dict | None:
    key = _chart_key(company_id, org_id)
    raw = _redis(["GET", key])
    if raw is None:
        raw = _mem_store.get(key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def delete_chart_data(company_id: str, org_id: str) -> bool:
    key = _chart_key(company_id, org_id)
    _redis(["DEL", key])
    _mem_store.pop(key, None)
    return True


# ──────────────────────────────────────────────────────────────
# Org Chart API
# ──────────────────────────────────────────────────────────────
@app.get("/api/orgchart/search")
def orgchart_search(q: str = "", companyId: str = ""):
    access_token = get_valid_token(companyId)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(
        "https://api.pipedrive.com/v1/persons/search",
        headers=headers,
        params={"term": q, "limit": 20, "fields": "name"},
        timeout=15,
    )
    if r.status_code != 200:
        return {"people": []}

    items = (r.json().get("data") or {}).get("items") or []
    people = []
    for item in items:
        p = item.get("item", {}) or {}
        org = p.get("organization") or {}
        people.append(
            {
                "pdId": p.get("id"),
                "name": p.get("name", ""),
                "title": p.get("job_title") or "",
                "org_name": org.get("name", "") if isinstance(org, dict) else "",
            }
        )
    return {"people": people}


@app.post("/api/orgchart/save")
async def orgchart_save(payload: dict):
    org_id     = str(payload.get("orgId", ""))
    company_id = str(payload.get("companyId", ""))
    chart_json = payload.get("chart", "")
    chart_name = payload.get("chartName", "Org Chart")

    if not org_id or not company_id or not chart_json:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    # No Pipedrive token required for saving — the chart belongs to us now.
    # We still validate the company has ever authenticated so random callers
    # can't write arbitrary keys into our store.
    if not get_valid_token(company_id):
        return JSONResponse({"error": "Not connected"}, status_code=401)

    save_chart_data(company_id, org_id, chart_name, chart_json)
    return {"ok": True}


@app.get("/api/orgchart/load")
def orgchart_load(orgId: str = "", companyId: str = ""):
    if not orgId or not companyId:
        return {}

    # Same light auth check
    if not get_valid_token(companyId):
        return JSONResponse({"error": "Not connected"}, status_code=401)

    data = load_chart_data(companyId, orgId)
    if data:
        return data
    return {}


@app.delete("/api/orgchart/delete")
async def orgchart_delete(orgId: str = "", companyId: str = ""):
    """Optional endpoint — wipe the stored chart for an org."""
    if not orgId or not companyId:
        return JSONResponse({"error": "Missing orgId or companyId"}, status_code=400)
    if not get_valid_token(companyId):
        return JSONResponse({"error": "Not connected"}, status_code=401)
    delete_chart_data(companyId, orgId)
    return {"ok": True}


@app.get("/api/orgs/search")
def orgs_search(q: str = "", companyId: str = ""):
    access_token = get_valid_token(companyId)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(
        "https://api.pipedrive.com/v1/organizations/search",
        headers=headers,
        params={"term": q, "limit": 10, "fields": "name"},
        timeout=15,
    )
    if r.status_code != 200:
        return {"orgs": []}

    items = (r.json().get("data") or {}).get("items") or []
    orgs = [{"id": i["item"]["id"], "name": i["item"]["name"]} for i in items if "item" in i]
    return {"orgs": orgs}


# Static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")