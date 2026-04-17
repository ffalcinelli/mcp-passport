from fastapi import FastAPI, Header, HTTPException, Request, Depends, Response
from fastapi.responses import StreamingResponse, RedirectResponse
import jwt
from typing import Optional
import json
import asyncio
import httpx
import os
import hashlib
import base64
import uuid

app = FastAPI()

# Configuration
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token/introspect"
CLIENT_ID = os.environ.get("CLIENT_ID", "mock-mcp")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "mock-mcp-secret")

# In-memory store for PAR requests and tokens (for mock purposes)
par_requests = {}
tokens = {"valid_token": {"active": True, "scope": "mcp:all"}}

def validate_dpop_proof(dpop: str, method: str, url: str, access_token: str):
    if not dpop:
        raise HTTPException(status_code=401, detail="Missing DPoP header")
    
    try:
        header = jwt.get_unverified_header(dpop)
        if header.get("typ") != "dpop+jwt":
            raise HTTPException(status_code=401, detail="Invalid DPoP typ")
            
        jwk_data = header.get("jwk")
        if not jwk_data:
            raise HTTPException(status_code=401, detail="Missing JWK in DPoP header")
            
        alg = jwt.algorithms.ECAlgorithm(jwt.algorithms.ECAlgorithm.SHA256)
        public_key = alg.from_jwk(json.dumps(jwk_data))
        
        payload = jwt.decode(dpop, public_key, algorithms=["ES256"])
        
        if payload.get("htm") != method:
            raise HTTPException(status_code=401, detail="Invalid htm in DPoP proof")
        if payload.get("htu") != url:
            # Handle potential localhost vs ::1 mismatch
            if not ("::1" in payload.get("htu") and "localhost" in url) and \
               not ("localhost" in payload.get("htu") and "::1" in url):
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

async def verify_auth(request: Request, authorization: Optional[str] = Header(None), dpop: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("DPoP "):
        # Check if we should fallback to Bearer if configured, but here we enforce DPoP
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Expected DPoP bound token.")
    
    access_token = authorization[5:].strip()
    if not access_token:
        raise HTTPException(status_code=401, detail="Empty DPoP token provided")

    # 1. Check local tokens first (for fully mock flow)
    if access_token in tokens:
        token_info = tokens[access_token]
        if not token_info["active"]:
            raise HTTPException(status_code=401, detail="Token is inactive or expired")
    else:
        # 2. Fallback to Introspect against real Keycloak if available
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    INTROSPECT_URL,
                    auth=(CLIENT_ID, CLIENT_SECRET),
                    data={"token": access_token},
                    timeout=5.0
                )
                if resp.status_code == 200:
                    introspection = resp.json()
                    if not introspection.get("active"):
                        raise HTTPException(status_code=401, detail="Token is inactive or expired")
                else:
                    raise HTTPException(status_code=401, detail="Token introspection failed")
            except Exception as e:
                print(f"Introspection error: {e}")
                raise HTTPException(status_code=401, detail="Auth server unreachable or token invalid")

    # 3. Validate DPoP proof
    url = str(request.url)
    try:
        validate_dpop_proof(dpop, request.method, url, access_token)
    except HTTPException as e:
        if e.status_code == 401:
            headers = {
                "WWW-Authenticate": f'DPoP error="invalid_token", resource_metadata="{request.base_url}.well-known/oauth-protected-resource"'
            }
            raise HTTPException(status_code=401, detail=e.detail, headers=headers)
        raise e

# --- OIDC Mock Endpoints ---

@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/openid-configuration")
async def discovery(request: Request):
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": f"{base}/realms/mcp",
        "authorization_endpoint": f"{base}/realms/mcp/protocol/openid-connect/auth",
        "token_endpoint": f"{base}/realms/mcp/protocol/openid-connect/token",
        "pushed_authorization_request_endpoint": f"{base}/realms/mcp/protocol/openid-connect/ext/par/request",
        "introspection_endpoint": f"{base}/realms/mcp/protocol/openid-connect/token/introspect",
        "dpop_signing_alg_values_supported": ["ES256"]
    }

@app.post("/realms/mcp/protocol/openid-connect/ext/par/request")
async def par_endpoint(request: Request):
    form_data = await request.form()
    request_uri = f"urn:ietf:params:oauth:request_uri:{uuid.uuid4()}"
    par_requests[request_uri] = dict(form_data)
    return {
        "request_uri": request_uri,
        "expires_in": 60
    }

@app.get("/realms/mcp/protocol/openid-connect/auth")
async def auth_endpoint(request_uri: str, redirect_uri: str, state: str):
    # Minimal mock auth page: just redirect back with a code
    if request_uri not in par_requests:
        raise HTTPException(status_code=400, detail="Invalid request_uri")
    
    code = f"mock_code_{uuid.uuid4()}"
    # Store code for token exchange
    par_requests[code] = par_requests.pop(request_uri)
    
    return RedirectResponse(url=f"{redirect_uri}?code={code}&state={state}")

@app.post("/realms/mcp/protocol/openid-connect/token")
async def token_endpoint(request: Request):
    form_data = await request.form()
    grant_type = form_data.get("grant_type")
    
    if grant_type == "authorization_code":
        code = form_data.get("code")
        if code not in par_requests:
            raise HTTPException(status_code=400, detail="Invalid code")
        
        access_token = f"mock_access_token_{uuid.uuid4()}"
        tokens[access_token] = {"active": True, "scope": par_requests[code].get("scope", "mcp:all")}
        
        return {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": 3600,
            "scope": tokens[access_token]["scope"]
        }
    
    raise HTTPException(status_code=400, detail="Unsupported grant_type")

# --- MCP Endpoints ---

@app.post("/rpc", dependencies=[Depends(verify_auth)])
async def handle_rpc(request: Request):
    payload = await request.json()
    method = payload.get("method")
    print(f"DEBUG: Received RPC request - Method: {method}, Payload: {payload}")
    
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
    
    if method == "notifications/initialized":
        return Response(content="{}", media_type="application/json")

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

    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "error": {"code": -32601, "message": "Method not found"}
    }

@app.get("/sse", dependencies=[Depends(verify_auth)])
async def sse_endpoint(request: Request):
    print(f"DEBUG: New SSE connection established from {request.client}")
    async def event_generator():
        while True:
            await asyncio.sleep(30)
            yield ": ping\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")
