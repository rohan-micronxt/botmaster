"""
WhatsApp Vendor Passthrough Proxy
Domain: botmaster.storenxt.in
Proxies all requests to: https://api.botmastersender.com/api/v3/

Multi-account token injection:
  - Client sends { "accountId": "<name>", ... } — no authToken needed
  - Proxy reads BOTMASTER_TOKEN_<NAME> from .env and injects authToken server-side
  - To add a new account: add BOTMASTER_TOKEN_<NAME>=<token> to .env
"""

import os
import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from dotenv import load_dotenv
import logging
import time

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

VENDOR_BASE_URL = "https://api.botmastersender.com/api/v3/"

# ──────────────────────────────────────────────────────────────────────────────
# IP WHITELIST
# Add or remove client IPs that are allowed to use this proxy.
# Supports both IPv4 and IPv6.
# Set to an empty list [] to DISABLE whitelisting (allow all — not recommended).
# ──────────────────────────────────────────────────────────────────────────────



WHITELISTED_IPS: list[str] = [
    "127.0.0.1",        # localhost (for local dev/testing)
    "::1",              # localhost IPv6
    # "103.21.244.10",  # example client server 1
    # "103.21.244.11",  # example client server 2
    # "49.50.72.100",   # example office IP
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ─── IP Resolution ────────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    """
    Resolve the real client IP address.
    Checks X-Forwarded-For and X-Real-IP headers first (set by Nginx/load balancer),
    then falls back to the direct connection IP.
    """
    # X-Forwarded-For may contain a chain: "client, proxy1, proxy2"
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return request.client.host if request.client else "unknown"


# ─── IP Whitelist Middleware ───────────────────────────────────────────────────



class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """
    Blocks all requests from IPs not in WHITELISTED_IPS.
    Whitelisting is skipped entirely when WHITELISTED_IPS is empty or disabled via class attribute.
    The /health endpoint is always allowed through for uptime checks.
    """

    ALWAYS_ALLOWED_PATHS = {"/health"}
    DISABLED = False  # Class-level toggle for disabling whitelist

    @classmethod
    def set_disabled(cls, value: bool):
        cls.DISABLED = value

    async def dispatch(self, request: Request, call_next):
        # Skip check for health probe
        if request.url.path in self.ALWAYS_ALLOWED_PATHS:
            return await call_next(request)

        # Skip check if whitelist is disabled via class or empty list
        if self.DISABLED or not WHITELISTED_IPS:
            if self.DISABLED:
                logger.warning("IP whitelisting is DISABLED via class attribute — all IPs are allowed")
            else:
                logger.warning("IP whitelisting is DISABLED — all IPs are allowed")
            return await call_next(request)

        client_ip = get_client_ip(request)

        if client_ip not in WHITELISTED_IPS:
            logger.warning(f"BLOCKED request from unauthorized IP: {client_ip} → {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "message": "Access denied: your IP address is not authorized to use this service.",
                    "ip": client_ip,
                },
            )

        logger.info(f"ALLOWED request from IP: {client_ip} → {request.url.path}")
        return await call_next(request)


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="WhatsApp Notification Proxy",
    description="Passthrough proxy for BotMaster WhatsApp vendor API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Order matters: IP check runs before CORS
app.add_middleware(IPWhitelistMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

SUPPORTED_ACTIONS = {
    "sendtemplate",
    "demo_send_template",
    "demo_send_template_busy",
    "demo_send_template_direct",
    "demo_send_message_direct",
}


def resolve_auth_token(body: dict) -> dict:
    """
    Inject authToken server-side from environment variables.

    Client sends { "accountId": "srinath", ... }
    Proxy looks up BOTMASTER_TOKEN_SRINATH from .env and injects authToken.

    To add a new account, add to .env:
        BOTMASTER_TOKEN_<ACCOUNTID_UPPERCASE>=<token>

    If accountId is not provided, falls back to BOTMASTER_TOKEN_DEFAULT.
    Raises HTTP 400 if no matching token is found.
    """
    body = dict(body)  # don't mutate caller's dict

    # Remove accountId from body — vendor doesn't know about it
    account_id = body.pop("accountId", "default").strip().upper()
    env_key = f"BOTMASTER_TOKEN_{account_id}"
    token = os.environ.get(env_key)

    if not token:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": f"No token configured for accountId '{account_id.lower()}'. "
                           f"Add {env_key}=<token> to the server .env file.",
            },
        )

    body["authToken"] = token
    return body


async def forward_to_vendor(action: str, body: dict) -> dict:
    """Forward the request to the vendor API and return the response."""
    vendor_url = f"{VENDOR_BASE_URL}?action={action}"

    # Inject authToken from env — strips accountId, adds authToken
    body = resolve_auth_token(body)

    forward_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    logger.info(f"Forwarding action={action} to {vendor_url}")
    start = time.time()

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(vendor_url, json=body, headers=forward_headers)

    elapsed = round((time.time() - start) * 1000, 2)
    logger.info(f"Vendor responded: status={response.status_code} in {elapsed}ms")

    try:
        return response.status_code, response.json()
    except Exception:
        return response.status_code, {"raw": response.text}


# ─── Routes ───────────────────────────────────────────────────────────────────




@app.get("/health")
async def health(request: Request):
    client_ip = get_client_ip(request)
    if IPWhitelistMiddleware.DISABLED:
        ip_whitelisting_status = "disabled (class)"
    elif WHITELISTED_IPS:
        ip_whitelisting_status = "enabled"
    else:
        ip_whitelisting_status = "disabled"
    return {
        "status": "ok",
        "proxy_target": VENDOR_BASE_URL,
        "ip_whitelisting": ip_whitelisting_status,
        "whitelisted_ip_count": len(WHITELISTED_IPS),
        "your_ip": client_ip,
    }




@app.get("/api/v1/whitelist")
async def list_whitelist(request: Request):
    """View current whitelisted IPs. Accessible only from a whitelisted IP (enforced by middleware)."""
    if IPWhitelistMiddleware.DISABLED:
        ip_whitelisting_status = "disabled (class)"
    elif WHITELISTED_IPS:
        ip_whitelisting_status = "enabled"
    else:
        ip_whitelisting_status = "disabled"
    return {
        "success": True,
        "ip_whitelisting": ip_whitelisting_status,
        "whitelisted_ips": WHITELISTED_IPS,
        "your_ip": get_client_ip(request),
    }



@app.post("/api/v1/")
async def proxy_action(request: Request, action: Optional[str] = None):
    """
    Generic passthrough endpoint.
    Mirrors: POST https://api.botmastersender.com/api/v1/?action=<action>

    Usage:
        POST https://botmaster.storenxt.in/api/v1/?action=demo_send_template
        Body: same JSON body as vendor API spec
    """
    # Resolve action from query param
    action = request.query_params.get("action", action)
    if not action:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Missing required query parameter: action",
                "supported_actions": sorted(SUPPORTED_ACTIONS),
            },
        )

    if action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": f"Unknown action: '{action}'",
                "supported_actions": sorted(SUPPORTED_ACTIONS),
            },
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=422,
            detail={"success": False, "message": "Invalid JSON body"},
        )

    try:
        status_code, vendor_response = await forward_to_vendor(action, body)
        return JSONResponse(content=vendor_response, status_code=status_code)
    except httpx.TimeoutException:
        logger.error("Vendor API timed out")
        raise HTTPException(
            status_code=504,
            detail={"success": False, "message": "Vendor API request timed out"},
        )
    except httpx.RequestError as e:
        logger.error(f"Vendor API connection error: {e}")
        raise HTTPException(
            status_code=502,
            detail={"success": False, "message": f"Could not reach vendor API: {str(e)}"},
        )


# ─── Dedicated route aliases (optional, for cleaner client URLs) ───────────────


@app.post("/api/v1/send-template")
async def send_template(request: Request):
    """Alias → ?action=demo_send_template"""
    return await _proxy("demo_send_template", request)


@app.post("/api/v1/send-template-busy")
async def send_template_busy(request: Request):
    """Alias → ?action=demo_send_template_busy"""
    return await _proxy("demo_send_template_busy", request)


@app.post("/api/v1/send-template-direct")
async def send_template_direct(request: Request):
    """Alias → ?action=demo_send_template_direct"""
    return await _proxy("demo_send_template_direct", request)


@app.post("/api/v1/send-message-direct")
async def send_message_direct(request: Request):
    """Alias → ?action=demo_send_message_direct"""
    return await _proxy("demo_send_message_direct", request)


async def _proxy(action: str, request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail={"success": False, "message": "Invalid JSON body"})
    try:
        status_code, vendor_response = await forward_to_vendor(action, body)
        return JSONResponse(content=vendor_response, status_code=status_code)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail={"success": False, "message": "Vendor API timed out"})
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail={"success": False, "message": str(e)})
