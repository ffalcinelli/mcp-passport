from fastapi import FastAPI, Header, HTTPException, Request, Depends, Response
from fastapi.responses import StreamingResponse
import jwt
from typing import Optional
import json
import asyncio
import httpx
import os
import hashlib
import base64

app = FastAPI()

# Configuration
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
EXTERNAL_KEYCLOAK_URL = os.environ.get("EXTERNAL_KEYCLOAK_URL", KEYCLOAK_URL).rstrip("/")
INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token/introspect"
CLIENT_ID = os.environ.get("CLIENT_ID", "mock-mcp")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "mock-mcp-secret")

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
        # Return 401 with resource_metadata fallback for unauthenticated requests
        headers = {
            "WWW-Authenticate": f'DPoP resource_metadata="{request.base_url}.well-known/oauth-protected-resource"'
        }
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Expected DPoP bound token.", headers=headers)
    
    access_token = authorization[5:].strip()
    if not access_token:
        raise HTTPException(status_code=401, detail="Empty DPoP token provided")

    # 1. Introspect token against Keycloak
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
                raise HTTPException(status_code=401, detail="Token introspection failed at Keycloak")
        except Exception as e:
            print(f"Introspection error: {e}")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=401, detail="Auth server unreachable")

    # 2. Validate DPoP proof
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

# --- Dynamic Discovery Endpoint ---

@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/openid-configuration")
async def discovery(request: Request):
    # This resource server tells the proxy to use Keycloak for authentication.
    # We use EXTERNAL_KEYCLOAK_URL so the client (host) can reach it.
    return {
        "issuer": f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp",
        "authorization_endpoint": f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/auth",
        "token_endpoint": f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token",
        "pushed_authorization_request_endpoint": f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/ext/par/request",
        "introspection_endpoint": f"{EXTERNAL_KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token/introspect",
        "dpop_signing_alg_values_supported": ["ES256"]
    }

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
