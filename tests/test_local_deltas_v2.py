"""Local deltas re-applied on top of upstream v2.0.0.

Upstream v2.0.0 already ships equivalent hardening (relay secret header,
TLS verify, no static sentinel). These tests pin the three things that are
ours and would silently regress if the next upstream merge drops them:

1. Relay workers buffer the request body before forwarding. A streamed body
   is one-time-use, so a redirect from the target upstream could not be
   replayed and surfaced as a 502 "body already used".
2. No referral code is baked in (upstream re-ships the author's code).
"""
from __future__ import annotations

import pytest

from zcode_gateway.config import GeneratorConfig
from zcode_gateway.relay_deploy import (
    CLOUDFLARE_WORKER_CODE,
    DENO_RELAY_CODE,
    NETLIFY_RELAY_CODE,
    VERCEL_RELAY_CODE,
)

WORKERS = {
    "cloudflare": CLOUDFLARE_WORKER_CODE,
    "vercel": VERCEL_RELAY_CODE,
    "deno": DENO_RELAY_CODE,
    "netlify": NETLIFY_RELAY_CODE,
}


@pytest.mark.parametrize("name,code", WORKERS.items())
def test_worker_buffers_the_request_body(name: str, code: str) -> None:
    assert "arrayBuffer()" in code, f"{name} worker forwards a one-time-use stream"
    assert "duplex" not in code, f"{name} worker still streams the body"


@pytest.mark.parametrize("name,code", WORKERS.items())
def test_worker_still_declares_a_secret_gate(name: str, code: str) -> None:
    assert "x-relay-secret" in code, f"{name} worker has no secret gate"


def test_config_defaults_have_no_referral_code() -> None:
    assert GeneratorConfig().invite_code == ""


def test_generator_manager_defaults_have_no_referral_code(tmp_path) -> None:
    from zcode_gateway.generator import GeneratorManager

    mgr = GeneratorManager(gen_dir=tmp_path)
    assert mgr._invite_code == ""


