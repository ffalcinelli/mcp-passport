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

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
INTROSPECT_URL = f"{KEYCLOAK_URL}/realms/mcp/protocol/openid-connect/token/introspect"
CLIENT_ID = os.environ.get("CLIENT_ID", "mock-mcp")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "mock-mcp-secret")

def validate_dpop_proof(dpop: str, method: str, url: str, access_token: str):
    if not dpop:
        raise HTTPException(status_code=401, detail="Missing DPoP header")
    
    try:
        # Decode without verification first to extract the JWK from the header
        header = jwt.get_unverified_header(dpop)
        if header.get("typ") != "dpop+jwt":
            raise HTTPException(status_code=401, detail="Invalid DPoP typ")
            
        jwk_data = header.get("jwk")
        if not jwk_data:
            raise HTTPException(status_code=401, detail="Missing JWK in DPoP header")
            
        # We assume ES256 here based on the rust implementation
        alg = jwt.algorithms.ECAlgorithm(jwt.algorithms.ECAlgorithm.SHA256)
        public_key = alg.from_jwk(json.dumps(jwk_data))
        
        # Verify the signature
        payload = jwt.decode(dpop, public_key, algorithms=["ES256"])
        
        # Validate htm and htu
        if payload.get("htm") != method:
            raise HTTPException(status_code=401, detail="Invalid htm in DPoP proof")
        if payload.get("htu") != url:
            raise HTTPException(status_code=401, detail="Invalid htu in DPoP proof")
            
        # Validate ath (Access Token Hash)
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
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Expected DPoP bound token.")
    
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
                timeout=10.0
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=401, detail="Token introspection failed at Keycloak")
            
            introspection = resp.json()
            if not introspection.get("active"):
                raise HTTPException(status_code=401, detail="Token is inactive or expired")
        except Exception as e:
            print(f"Introspection error: {e}")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=401, detail="Auth server unreachable")

    # 2. Validate DPoP proof and 'ath' claim
    url = str(request.url)
    validate_dpop_proof(dpop, request.method, url, access_token)

@app.post("/rpc", dependencies=[Depends(verify_auth)])
async def handle_rpc(request: Request):
    payload = await request.json()
    method = payload.get("method")
    print(f"DEBUG: Received RPC request - Method: {method}, Payload: {payload}")
    
    # Mocking standard MCP tools/list
    if method == "initialize":
        requested_version = payload.get("params", {}).get("protocolVersion", "2024-11-05")
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "protocolVersion": requested_version,
                "capabilities": {
                    "tools": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "mock-mcp-server",
                    "version": "1.0.0"
                }
            }
        }
    
    if method == "notifications/initialized":
        # Return empty body with 200 OK for notifications
        return Response(content="{}", media_type="application/json")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "mock_tool",
                        "description": "A mock tool for testing",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "input": {"type": "string"}
                            }
                        }
                    }
                ]
            }
        }

    if method == "tools/call":
        tool_name = payload.get("params", {}).get("name")
        if tool_name == "mock_tool":
            args = payload.get("params", {}).get("arguments", {})
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Successfully executed mock_tool with input: {args.get('input', 'none')}"
                        }
                    ]
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
        # Keep connection open but don't send confusing non-standard notifications
        while True:
            await asyncio.sleep(30)
            yield ": ping\n\n"
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")
