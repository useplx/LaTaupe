from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi import Request as Incoming
from fastapi.responses import JSONResponse, Response

from .engine import Engine
from .features import Request
from .policy import Action
from .reports import Reporter

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length", "date", "server",
}


def create(engine: Engine, reports: Reporter, upstream: str,
           timeout: float = 10.0, max_body_bytes: int = 1_048_576) -> FastAPI:
    client = httpx.AsyncClient(base_url=upstream.rstrip("/"), timeout=timeout,
                               follow_redirects=False)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await client.aclose()

    app = FastAPI(title="LaTaupe WAF", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def forward(request: Incoming, path: str) -> Response:
        del path
        body = await request.body()
        if len(body) > max_body_bytes:
            return JSONResponse({"blocked": True, "reason": "request body too large"}, status_code=413)
        headers = {key.lower(): value for key, value in request.headers.items()}
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        remote = request.client.host if request.client else "unknown"
        decision = engine.inspect(Request(request.method, target, headers, body), remote)
        if decision.new_mitigation:
            reports.submit(decision.mitigation_id)
        common = {"X-LaTaupe-Risk": f"{decision.risk:.4f}",
                  "X-LaTaupe-Mitigation": str(decision.mitigation_id)}
        if decision.action is Action.BLOCK:
            return JSONResponse({"blocked": True, "mitigation_id": decision.mitigation_id,
                                 "attack_type": decision.attack_type, "risk": decision.risk},
                                status_code=403, headers=common)
        forwarded = {key: value for key, value in request.headers.items()
                     if key.lower() not in HOP_HEADERS}
        try:
            response = await client.request(request.method, target, headers=forwarded, content=body)
        except httpx.RequestError:
            return JSONResponse({"error": "upstream unavailable"}, status_code=502, headers=common)
        response_headers = {key: value for key, value in response.headers.items()
                            if key.lower() not in HOP_HEADERS}
        response_headers.update(common)
        return Response(response.content, response.status_code, response_headers,
                        response.headers.get("content-type"))

    return app
