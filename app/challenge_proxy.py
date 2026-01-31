"""
Challenge Proxy - Routes challenge.sion-ctf.pro/{challenge_id}/... to container ports.

This lightweight FastAPI app runs on port 5000 and proxies requests to the correct
Docker container based on the challenge's public_path.

Usage:
    uvicorn app.challenge_proxy:app --host 0.0.0.0 --port 5000
"""

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from app.db import get_connection

logger = logging.getLogger(__name__)

# Shared httpx client for connection pooling
_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage httpx client lifecycle."""
    global _http_client
    _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
    logger.info("Challenge proxy started")
    yield
    await _http_client.aclose()
    logger.info("Challenge proxy stopped")


app = FastAPI(
    title="Challenge Proxy",
    description="Routes requests to CTF challenge containers",
    lifespan=lifespan,
)


def get_container_url(public_path: str) -> str | None:
    """Look up container URL by public_path."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT container_url FROM challenges WHERE public_path = ? AND status IN ('running', 'validated', 'unverified')",
            (public_path,),
        ).fetchone()
        if row:
            return row["container_url"]
    return None


@app.get("/", response_class=HTMLResponse)
async def root():
    """Root page - show info about accessing challenges."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Challenge Proxy</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #eee; }
            h1 { color: #00d4ff; }
            code { background: #333; padding: 2px 6px; border-radius: 4px; }
            a { color: #00d4ff; }
        </style>
    </head>
    <body>
        <h1>Challenge Proxy</h1>
        <p>This server routes requests to CTF challenge containers.</p>
        <p>Access your challenge at: <code>/{challenge_id}/</code></p>
        <p>Go to <a href="https://sion-ctf.pro">sion-ctf.pro</a> to generate challenges.</p>
    </body>
    </html>
    """


@app.api_route(
    "/{public_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_request(request: Request, public_path: str):
    """Proxy requests to the correct container based on public_path prefix."""
    if not _http_client:
        return Response(content="Proxy not ready", status_code=503)

    # Extract challenge ID from path (first segment)
    path_parts = public_path.split("/", 1)
    challenge_id = path_parts[0]
    remaining_path = path_parts[1] if len(path_parts) > 1 else ""

    if not challenge_id:
        return Response(content="No challenge ID provided", status_code=400)

    # Look up the container URL
    container_url = get_container_url(challenge_id)
    if not container_url:
        return Response(
            content=f"Challenge '{challenge_id}' not found or not running",
            status_code=404,
        )

    # Build the target URL (strip the challenge_id prefix)
    target_url = f"{container_url}/{remaining_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Forward the request
    try:
        # Get request body
        body = await request.body()

        # Build headers (exclude host, it will be set by httpx)
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)  # Let httpx calculate

        # Add X-Forwarded headers
        headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
        headers["X-Forwarded-Proto"] = request.url.scheme
        headers["X-Forwarded-Host"] = request.headers.get("host", "")
        headers["X-Challenge-ID"] = challenge_id

        # Make the proxied request
        response = await _http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        # Build response headers (filter hop-by-hop headers)
        response_headers = {}
        hop_by_hop = {
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
        }
        for key, value in response.headers.items():
            if key.lower() not in hop_by_hop:
                # Rewrite cookie paths to include challenge prefix
                if key.lower() == "set-cookie":
                    # Add path prefix for cookie isolation
                    if "; path=" not in value.lower():
                        value = f"{value}; Path=/{challenge_id}/"
                response_headers[key] = value

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
        )

    except httpx.ConnectError:
        logger.warning(f"Cannot connect to container for challenge {challenge_id}")
        return Response(
            content="Challenge container is not responding. It may have stopped.",
            status_code=502,
        )
    except httpx.TimeoutException:
        logger.warning(f"Timeout connecting to challenge {challenge_id}")
        return Response(content="Challenge container timed out", status_code=504)
    except Exception as e:
        logger.exception(f"Error proxying request to challenge {challenge_id}")
        return Response(content=f"Proxy error: {str(e)}", status_code=500)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
