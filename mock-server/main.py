from fastapi import FastAPI, Header, HTTPException, Request, Depends, Response
from fastapi.responses import JSONResponse, StreamingResponse
import jwt
from typing import Optional
import json
import asyncio
import httpx
import os
import hashlib
import base64
import urllib.parse

app = FastAPI()

def sanitize_url_for_header(url: str) -> str:
    """Sanitize URL to prevent HTTP header injection vulnerabilities."""
    return urllib.parse.quote(str(url), safe=":/%#?=@[]!$&'()*+,;-._~")

# Configuration
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
EXTERNAL_KEYCLOAK_URL = os.environ.get("EXTERNAL_KEYCLOAK_URL", KEYCLOAK_URL).rstrip("/")
INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token/introspect"
CLIENT_ID = os.environ.get("CLIENT_ID", "mock-mcp")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "mock-mcp-secret")

def is_valid_htu(htu: str, url: str) -> bool:
    if not htu or not url:
        return False
    if htu == url:
        return True
    try:
        parsed_htu = urllib.parse.urlsplit(htu)
        parsed_url = urllib.parse.urlsplit(url)

        if (parsed_htu.scheme != parsed_url.scheme or
            parsed_htu.port != parsed_url.port or
            parsed_htu.path != parsed_url.path or
            parsed_htu.query != parsed_url.query):
            return False

        allowed_hosts = {"localhost", "::1", "127.0.0.1"}
        if parsed_htu.hostname in allowed_hosts and parsed_url.hostname in allowed_hosts:
            return True

        return False
    except Exception:
        return False

def validate_dpop_proof(dpop: str, method: str, url: str, access_token: str):
    if not dpop:
        raise HTTPException(status_code=401, detail="Missing DPoP header")
    
    try:
        # 1. Peek at the header to get the JWK
        header = jwt.get_unverified_header(dpop)
        if header.get("typ") != "dpop+jwt":
            raise HTTPException(status_code=401, detail="Invalid DPoP typ")
            
        jwk_data = header.get("jwk")
        if not jwk_data:
            raise HTTPException(status_code=401, detail="Missing JWK in DPoP header")
            
        # 2. Convert JWK to public key for validation
        public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk_data))
        
        # 3. Decode and validate (PyJWT >= 2.12.0 handles 'crit' automatically if present)
        payload = jwt.decode(
            dpop, 
            public_key, 
            algorithms=["ES256"],
            options={"require": ["jti", "htm", "htu", "iat"]}
        )
        
        if payload.get("htm") != method:
            raise HTTPException(status_code=401, detail="Invalid htm in DPoP proof")
        if not is_valid_htu(payload.get("htu"), url):
            raise HTTPException(status_code=401, detail=f"Invalid htu in DPoP proof. Expected {url}, got {payload.get('htu')}")
            
        ath = payload.get("ath")
        if not ath:
            raise HTTPException(status_code=401, detail="Missing ath in DPoP proof")
        
        sha256 = hashlib.sha256(access_token.encode()).digest()
        expected_ath = base64.urlsafe_b64encode(sha256).decode().rstrip("=")
        if ath != expected_ath:
            raise HTTPException(status_code=401, detail="Mismatched ath in DPoP proof")
            
        return jwk_data
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=401, detail=f"Invalid DPoP proof: {str(e)}")

def resource_metadata_url(request: Request) -> str:
    """RFC 9728 path-inserted metadata URL for the /rpc MCP endpoint."""
    return sanitize_url_for_header(f"{request.base_url}.well-known/oauth-protected-resource/rpc")


def challenge(request: Request, error: Optional[str] = None) -> dict:
    value = f'Bearer resource_metadata="{resource_metadata_url(request)}", scope="openid"'
    if error:
        value += f', error="{error}"'
    return {"WWW-Authenticate": value}


async def verify_auth(request: Request, authorization: Optional[str] = Header(None), dpop: Optional[str] = Header(None)):
    scheme, _, access_token = (authorization or "").partition(" ")
    if scheme not in ("Bearer", "DPoP") or not access_token.strip():
        raise HTTPException(status_code=401, detail="Missing access token", headers=challenge(request))
    access_token = access_token.strip()

    # 1. Introspect token against Keycloak
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                INTROSPECT_URL,
                auth=(CLIENT_ID, CLIENT_SECRET),
                data={"token": access_token},
                timeout=5.0
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=401, detail="Token introspection failed at Keycloak", headers=challenge(request))
            introspection = resp.json()
            if not introspection.get("active"):
                raise HTTPException(status_code=401, detail="Token is inactive or expired", headers=challenge(request, "invalid_token"))
        except HTTPException:
            raise
        except Exception as e:
            print(f"Introspection error: {e}")
            raise HTTPException(status_code=401, detail="Auth server unreachable", headers=challenge(request))

    # 2. Validate the DPoP proof and its binding to the token (cnf.jkt)
    url = str(request.url)
    try:
        jwk_data = validate_dpop_proof(dpop, request.method, url, access_token)
    except HTTPException as e:
        if e.status_code == 401:
            raise HTTPException(status_code=401, detail=e.detail, headers=challenge(request, "invalid_token"))
        raise
    expected_jkt = (introspection.get("cnf") or {}).get("jkt")
    if expected_jkt and jwk_thumbprint(jwk_data) != expected_jkt:
        raise HTTPException(status_code=401, detail="DPoP key does not match the token", headers=challenge(request, "invalid_token"))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of an EC P-256 JWK."""
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")

# --- Dynamic Discovery Endpoint ---

@app.get("/.well-known/oauth-protected-resource/rpc")
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request):
    """RFC 9728 Protected Resource Metadata. The authorization server (Keycloak)
    publishes its own metadata; MCP clients discover it from here."""
    return {
        "resource": f"{request.base_url}rpc",
        "authorization_servers": [f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp"],
        "scopes_supported": ["openid"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Mock MCP Server",
    }

# --- MCP Endpoints ---

MODERN_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = [MODERN_VERSION, "2025-11-25"]


def rpc_error(status: int, id_, code: int, message: str, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(status_code=status, content={"jsonrpc": "2.0", "id": id_, "error": error})


def decode_header(value: Optional[str]) -> Optional[str]:
    if value and value.startswith("=?base64?") and value.endswith("?="):
        return base64.b64decode(value[len("=?base64?"):-2]).decode()
    return value


def check_modern_headers(request: Request, payload: dict):
    """MCP 2026-07-28 Streamable HTTP: headers must mirror the body."""
    id_ = payload.get("id")
    params = payload.get("params") or {}
    version = params["_meta"]["io.modelcontextprotocol/protocolVersion"]
    if request.headers.get("mcp-protocol-version") != version:
        return rpc_error(400, id_, -32020, "Header mismatch: MCP-Protocol-Version")
    if version not in SUPPORTED_VERSIONS:
        return rpc_error(400, id_, -32022, "Unsupported protocol version",
                         {"supported": SUPPORTED_VERSIONS, "requested": version})
    if request.headers.get("mcp-method") != payload.get("method"):
        return rpc_error(400, id_, -32020, "Header mismatch: Mcp-Method")
    field = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}.get(payload.get("method"))
    if field and decode_header(request.headers.get("mcp-name")) != params.get(field):
        return rpc_error(400, id_, -32020, "Header mismatch: Mcp-Name")
    return None


@app.get("/rpc")
@app.delete("/rpc")
async def rpc_other_methods():
    # 2026-07-28 has no standalone GET stream and no sessions.
    return Response(status_code=405)


@app.post("/rpc", dependencies=[Depends(verify_auth)])
async def handle_rpc(request: Request):
    payload = await request.json()
    method = payload.get("method")
    print(f"DEBUG: Received RPC request - Method: {method}, Payload: {payload}")

    meta = (payload.get("params") or {}).get("_meta") or {}
    modern = "io.modelcontextprotocol/protocolVersion" in meta
    if modern:
        mismatch = check_modern_headers(request, payload)
        if mismatch is not None:
            return mismatch

    if "id" not in payload:
        # Notifications are acknowledged without a body.
        return Response(status_code=202)

    if modern and method == "server/discover":
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "resultType": "complete",
                "supportedVersions": SUPPORTED_VERSIONS,
                "capabilities": {"tools": {"listChanged": True}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"}},
            }
        }
    
    if method == "initialize":
        requested_version = payload.get("params", {}).get("protocolVersion", "2024-11-05")
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "protocolVersion": requested_version,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"}
            }
        }
    
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "tools": [{
                    "name": "mock_tool",
                    "description": "A mock tool for testing",
                    "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}}
                }]
            }
        }

    if method == "tools/call":
        params = payload.get("params", {})
        name = params.get("name")
        if name == "mock_tool":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"Mock tool called successfully with args: {params.get('arguments')}"}]
                }
            }

    return rpc_error(404 if modern else 200, payload.get("id"), -32601, "Method not found")

@app.get("/sse", dependencies=[Depends(verify_auth)])
async def sse_endpoint(request: Request):
    print(f"DEBUG: New SSE connection established from {request.client}")
    async def event_generator():
        while True:
            await asyncio.sleep(30)
            yield ": ping\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")
