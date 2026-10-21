"""FastAPI dependencies: auth and state access."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from .state import AppState


def _is_loopback(request: Request) -> bool:
    client = request.client.host if request.client else ""
    return client in ("127.0.0.1", "::1", "localhost")


def _is_internal(request: Request, state: AppState, supplied: str) -> bool:
    """The per-process internal token, accepted only from loopback.

    There is deliberately no static fallback value: a sentinel that ships in
    a public repo is a public secret, and any local process could use it to
    drive the admin API. Children get the real token over the environment
    (ZAI_GATEWAY_INTERNAL_TOKEN).
    """
    if not supplied:
        return False
    if not _is_loopback(request):
        return False
    return hmac.compare_digest(state.internal_token, supplied)


def get_state(request: Request) -> AppState:
    return request.app.state.app_state


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # anthropic clients may send x-api-key
    return request.headers.get("x-api-key", "").strip()


async def client_key(request: Request) -> str:
    """Validate a client key. Localhost + require_client_key=false lets anything through."""
    state = get_state(request)
    cfg = state.cfg.server
    if not cfg.require_client_key:
        return "anonymous"

    supplied = _bearer(request)
    if not supplied:
        raise HTTPException(status_code=401, detail="missing API key")

    # Admin key or internal sentinel can also authenticate client routes
    if hmac.compare_digest(state.cfg.server.admin_key, supplied) or _is_internal(request, state, supplied):
        return "admin"

    for entry in cfg.client_keys:
        if hmac.compare_digest(entry.key, supplied):
            if entry.rpm > 0:
                allowed, retry_after = state.limiter.check(entry.key, entry.rpm)
                if not allowed:
                    raise HTTPException(
                        status_code=429,
                        detail="rate limit exceeded for this API key",
                        headers={"Retry-After": str(int(retry_after) + 1)},
                    )
            return entry.name
    raise HTTPException(status_code=401, detail="invalid API key")


async def admin_key(request: Request) -> str:
    state = get_state(request)
    supplied = _bearer(request)
    if _is_internal(request, state, supplied) or hmac.compare_digest(state.cfg.server.admin_key, supplied):
        return "admin"
    raise HTTPException(status_code=403, detail="invalid admin key")
