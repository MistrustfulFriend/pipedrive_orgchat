import os
import json
import secrets
import requests
import time
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from urllib.parse import urlencode

from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

# Allow Pipedrive to load the panel in an iframe
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.pipedrive.com", "https://*.pipedrive.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IframeHeadersMiddleware(BaseHTTPMiddleware):
    """Remove X-Frame-Options and set permissive CSP so Pipedrive can embed us."""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        # Allow framing by Pipedrive
        response.headers.pop("x-frame-options", None)
        response.headers["content-security-policy"] = (
            "frame-ancestors https://app.pipedrive.com https://*.pipedrive.com 'self'"
        )
        return response

app.add_middleware(IframeHeadersMiddleware)

BASE_URL             = os.getenv("BASE_URL", "https://orgchart.onrender.com")
PIPEDRIVE_CLIENT_ID  = os.getenv("PIPEDRIVE_CLIENT_ID", "")
REDIRECT_URI         = f"{BASE_URL}/oauth/callback"

UPSTASH_URL   = os.getenv("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")

_mem_store:  dict = {}
_state_store: dict = {}

SENTINEL = "📊 [ORG_CHART_DATA_v1]"


# ── Redis helpers ─────────────────────────────────────────────────────────────

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
        return r.json().get("result") if r.status_code == 200 else None
    except Exception:
        return None


# ── Token storage ─────────────────────────────────────────────────────────────

def save_tokens(company_id, access_token, refresh_token, expires_in):
    expires_at = int(time.time()) + int(expires_in) - 60
    data = json.dumps({"access_token": access_token, "refresh_token": refresh_token, "expires_at": expires_at})
    key  = f"oc:tokens:{company_id}"
    result = _redis(["SET", key, data, "EX", str(int(expires_in) + 86400)])
    if result is None:
        _mem_store[key] = data


def load_tokens(company_id):
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


def save_oauth_state(state):
    key = f"oc:state:{state}"
    result = _redis(["SET", key, "1", "EX", "600"])
    if result is None:
        _state_store[state] = int(time.time()) + 600


def consume_oauth_state(state):
    key = f"oc:state:{state}"
    result = _redis(["GETDEL", key])
    if result is not None:
        return result == "1"
    exp = _state_store.pop(state, None)
    if exp is not None:
        return int(time.time()) < exp
    return bool(state)


def refresh_access_token(company_id: str, refresh_token: str):
    client_id     = PIPEDRIVE_CLIENT_ID
    client_secret = os.getenv("PIPEDRIVE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None
    try:
        r = requests.post(
            "https://oauth.pipedrive.com/oauth/token",
            data={
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "client_id":     client_id,
                "client_secret": client_secret,
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
    if int(time.time()) >= tokens["expires_at"] - 300:
        return refresh_access_token(company_id, tokens["refresh_token"])
    return tokens["access_token"]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return RedirectResponse("/panel")


@app.get("/panel")
def panel():
    return FileResponse("static/panel.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/oauth/start")
def oauth_start():
    if not PIPEDRIVE_CLIENT_ID:
        return JSONResponse({"error": "Missing PIPEDRIVE_CLIENT_ID env var"}, status_code=500)
    state = secrets.token_urlsafe(32)
    save_oauth_state(state)
    params = urlencode({
        "client_id":     PIPEDRIVE_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "state":         state,
    })
    return RedirectResponse(f"https://oauth.pipedrive.com/marketplace/oauth/authorize?{params}")


@app.get("/oauth/callback")
def oauth_callback(request: Request):
    code  = request.query_params.get("code")
    state = request.query_params.get("state", "")

    if not state or not consume_oauth_state(state):
        return JSONResponse({"error": "Invalid or expired state."}, status_code=400)
    if not code:
        return JSONResponse({"error": "No authorisation code returned."}, status_code=400)

    client_secret = os.getenv("PIPEDRIVE_CLIENT_SECRET", "")
    if not PIPEDRIVE_CLIENT_ID or not client_secret:
        return JSONResponse({"error": "Missing client credentials."}, status_code=500)

    r = requests.post(
        "https://oauth.pipedrive.com/oauth/token",
        data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,
            "client_id":     PIPEDRIVE_CLIENT_ID,
            "client_secret": client_secret,
        },
        timeout=30,
    )
    if r.status_code != 200:
        return JSONResponse({"error": "Token exchange failed", "body": r.text}, status_code=400)

    tokens        = r.json()
    access_token  = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    expires_in    = tokens.get("expires_in", 3600)

    me = requests.get(
        "https://api.pipedrive.com/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    me.raise_for_status()
    company_id = str(me.json()["data"]["company_id"])

    save_tokens(company_id, access_token, refresh_token, int(expires_in))
    return FileResponse("static/oauth_success.html")


@app.get("/api/status")
def api_status(companyId: str = ""):
    if not companyId:
        return {"connected": False}
    return {"connected": bool(get_valid_token(companyId))}


# ── Org Chart: search persons ─────────────────────────────────────────────────

@app.get("/api/orgchart/search")
def orgchart_search(q: str = "", companyId: str = ""):
    """Search Pipedrive persons by name across the whole account."""
    access_token = get_valid_token(companyId)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
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
            p   = item.get("item", {})
            org = p.get("organization") or {}
            people.append({
                "pdId":     p.get("id"),
                "name":     p.get("name", ""),
                "title":    p.get("job_title") or "",
                "org_name": org.get("name", "") if isinstance(org, dict) else "",
            })
        return {"people": people}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Org Chart: save ───────────────────────────────────────────────────────────

@app.post("/api/orgchart/save")
async def orgchart_save(payload: dict):
    """
    Saves the chart JSON as a pinned note on the Pipedrive organisation.
    Updates the same note on subsequent saves (no duplicates).
    chart_id is the local canvas ID (allows multiple charts per org in future).
    """
    org_id     = str(payload.get("orgId", ""))
    company_id = str(payload.get("companyId", ""))
    chart_json = payload.get("chart", "")
    chart_name = payload.get("chartName", "Org Chart")

    if not org_id or not company_id or not chart_json:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    access_token = get_valid_token(company_id)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers   = {"Authorization": f"Bearer {access_token}"}
    note_body = f"{SENTINEL}\nName: {chart_name}\n{chart_json}"

    try:
        # Find existing chart note for this org
        existing_id = None
        nr = requests.get(
            "https://api.pipedrive.com/v1/notes",
            headers=headers,
            params={"org_id": org_id, "limit": 50},
            timeout=15,
        )
        if nr.status_code == 200:
            for note in (nr.json().get("data") or []):
                if note.get("content", "").startswith(SENTINEL):
                    existing_id = note["id"]
                    break

        if existing_id:
            r = requests.put(
                f"https://api.pipedrive.com/v1/notes/{existing_id}",
                headers=headers,
                json={"content": note_body},
                timeout=15,
            )
        else:
            r = requests.post(
                "https://api.pipedrive.com/v1/notes",
                headers=headers,
                json={
                    "content":  note_body,
                    "org_id":   int(org_id),
                    "pinned_to_organization_flag": 1,
                },
                timeout=15,
            )

        if r.status_code in (200, 201):
            return {"ok": True, "note_id": r.json().get("data", {}).get("id")}
        return JSONResponse({"error": "Pipedrive error", "detail": r.text}, status_code=500)

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Org Chart: load ───────────────────────────────────────────────────────────

@app.get("/api/orgchart/load")
def orgchart_load(orgId: str = "", companyId: str = ""):
    """Load the saved chart from the pinned note on the organisation."""
    if not orgId or not companyId:
        return {}

    access_token = get_valid_token(companyId)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        r = requests.get(
            "https://api.pipedrive.com/v1/notes",
            headers=headers,
            params={"org_id": orgId, "limit": 50},
            timeout=15,
        )
        if r.status_code != 200:
            return {}

        for note in (r.json().get("data") or []):
            content = note.get("content", "")
            if content.startswith(SENTINEL):
                lines      = content.split("\n", 2)
                chart_name = lines[1].replace("Name: ", "").strip() if len(lines) > 1 else "Org Chart"
                chart_json = lines[2].strip() if len(lines) > 2 else ""
                return {"chart": chart_json, "chartName": chart_name}

        return {}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Org search (for the org picker on the panel) ──────────────────────────────

@app.get("/api/orgs/search")
def orgs_search(q: str = "", companyId: str = ""):
    """Search Pipedrive organisations by name."""
    access_token = get_valid_token(companyId)
    if not access_token:
        return JSONResponse({"error": "Not connected"}, status_code=401)

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        r = requests.get(
            "https://api.pipedrive.com/v1/organizations/search",
            headers=headers,
            params={"term": q, "limit": 10, "fields": "name"},
            timeout=15,
        )
        if r.status_code != 200:
            return {"orgs": []}

        items = (r.json().get("data") or {}).get("items") or []
        orgs  = [{"id": i["item"]["id"], "name": i["item"]["name"]} for i in items if "item" in i]
        return {"orgs": orgs}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


app.mount("/static", StaticFiles(directory="static"), name="static")