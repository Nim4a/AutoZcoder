"""Relay shared-key auth: workers must reject requests without the key.

A relay without a secret is an open proxy on the deployer's edge account.
These tests cover the four worker templates, the deployers that bake the
secret in, and the gateway side that sends it.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from zcode_gateway.relay_deploy import (
    CLOUDFLARE_WORKER_CODE,
    DENO_RELAY_CODE,
    NETLIFY_RELAY_CODE,
    RELAY_KEY_HEADER,
    VERCEL_RELAY_CODE,
    _build_netlify_zip,
    deploy_cloudflare,
    deploy_deno,
    deploy_netlify,
    deploy_vercel,
    new_relay_secret,
    ping_relay,
    render_worker,
)
from zcode_gateway.relay_manager import RelayManager
from zcode_gateway.upstream import TransportError, UpstreamClient, UpstreamConfig

TEMPLATES = {
    "cloudflare": CLOUDFLARE_WORKER_CODE,
    "vercel": VERCEL_RELAY_CODE,
    "deno": DENO_RELAY_CODE,
    "netlify": NETLIFY_RELAY_CODE,
}


# --------------------------------------------------------------------------- #
# templates
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_every_template_checks_the_key(name):
    code = TEMPLATES[name]
    assert RELAY_KEY_HEADER in code, f"{name} worker never reads the key header"
    assert '"unauthorized"' in code, f"{name} worker does not reject a bad key"
    # the key must be stripped before the request is forwarded upstream
    forwarding = code.split('"unauthorized"')[-1]
    assert RELAY_KEY_HEADER in forwarding, f"{name} worker may leak the key upstream"
    assert (f'delete("{RELAY_KEY_HEADER}")' in forwarding
            or f'"{RELAY_KEY_HEADER}"' in forwarding
            or 'lower === "x-relay-key"' in forwarding), \
        f"{name} worker forwards the key upstream"


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_template_is_not_valid_without_a_substituted_secret(name):
    """A hand-copied worker must fail closed, not run with a public secret."""
    code = TEMPLATES[name]
    assert "__RELAY_SECRET__" in code
    rendered = render_worker(code, "s3cr3t")
    assert "__RELAY_SECRET__" not in rendered
    # the secret is embedded as a JSON string literal
    assert '"s3cr3t"' in rendered


def test_render_worker_escapes_the_secret():
    rendered = render_worker(CLOUDFLARE_WORKER_CODE, 'a"b\\c')
    # the secret lands as a JSON string literal, so the raw value never
    # appears unescaped in the worker source
    assert 'a"b\\c' not in rendered
    assert json.dumps('a"b\\c') in rendered
    assert json.loads(json.dumps('a"b\\c')) == 'a"b\\c'


def test_new_relay_secret_is_unique_and_long():
    a, b = new_relay_secret(), new_relay_secret()
    assert a != b
    assert len(a) >= 32


# --------------------------------------------------------------------------- #
# deployers bake the secret in
# --------------------------------------------------------------------------- #

def test_deploy_cloudflare_bakes_the_secret(monkeypatch):
    import requests

    captured = {}

    def mock_request(method, url, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "subdomain" in url and method == "get":
            resp.json.return_value = {"success": True, "result": {"subdomain": "my-sub"}}
        elif "subdomain" in url and method == "post":
            # per-script enable: the deployer refuses a URL whose workers.dev
            # route did not actually come up
            resp.json.return_value = {"success": True, "result": {"enabled": True}}
        else:
            resp.json.return_value = {"success": True}
        return resp

    def mock_put(url, **kwargs):
        captured["files"] = kwargs.get("files")
        return mock_request("put", url, **kwargs)

    monkeypatch.setattr(requests, "put", mock_put)
    monkeypatch.setattr(requests, "post", lambda url, **kwargs: mock_request("post", url, **kwargs))
    monkeypatch.setattr(requests, "get", lambda url, **kwargs: mock_request("get", url, **kwargs))

    res = deploy_cloudflare("acc123", "token_xyz", "my-cf")
    assert res["ok"] is True
    key = res["relay_key"]
    assert key
    uploaded = captured["files"]["index.js"][1].decode("utf-8")
    assert f'"{key}"' in uploaded
    assert "__RELAY_SECRET__" not in uploaded


def test_deploy_vercel_bakes_the_secret(monkeypatch):
    import requests

    captured = {}

    def mock_post(url, **kwargs):
        payload = kwargs.get("json") or {}
        if "files" in payload:
            captured["files"] = payload["files"]
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.json.return_value = {"id": "d1", "uid": "d1", "projectId": "p1",
                                  "readyState": "READY", "url": "my-cf.vercel.app"}
        return resp

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"id": "d1", "uid": "d1", "projectId": "p1",
                                  "readyState": "READY", "url": "my-cf.vercel.app"}
        return resp

    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests, "get", mock_get)
    monkeypatch.setattr(requests, "patch", lambda url, **kwargs: mock_post(url, **kwargs))

    res = deploy_vercel("tok", "my-cf")
    key = res["relay_key"]
    assert key
    files = {f["file"]: f["data"] for f in captured.get("files", [])}
    assert f'"{key}"' in files.get("api/relay.js", "")


def test_deploy_deno_bakes_the_secret(monkeypatch):
    import requests

    captured = {}

    def mock_post(url, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "/deploy" in url:
            captured["deploy"] = kwargs.get("json")
            resp.json.return_value = {"id": "r1"}
        elif "/revisions/" in url:
            resp.json.return_value = {"id": "r1", "status": "succeeded"}
        else:
            resp.json.return_value = {"id": "a1"}
        return resp

    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests, "get", lambda url, **kwargs: mock_post(url, **kwargs))
    monkeypatch.setattr(requests, "delete", lambda url, **kwargs: mock_post(url, **kwargs))

    res = deploy_deno("tok", "myorg.deno.net", "my-dn")
    key = res["relay_key"]
    assert key
    content = captured["deploy"]["assets"]["main.ts"]["content"]
    assert f'"{key}"' in content


def test_deploy_netlify_bakes_the_secret(monkeypatch):
    import requests

    captured = {}
    secret = "netkey"
    _, fn_sha256 = _build_netlify_zip(secret)

    def mock_post(url, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "/deploys" in url:
            resp.json.return_value = {"id": "d1", "required": [],
                                      "required_functions": [fn_sha256]}
        else:
            resp.json.return_value = {"id": "s1", "ssl_url": "https://site.netlify.app",
                                      "site_id": "s1"}
        return resp

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"state": "ready"}
        return resp

    def mock_put(url, **kwargs):
        captured["put"] = kwargs.get("data")
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        return resp

    monkeypatch.setattr(requests, "post", mock_post)
    monkeypatch.setattr(requests, "get", mock_get)
    monkeypatch.setattr(requests, "put", mock_put)

    res = deploy_netlify("tok", "my-site", relay_secret=secret)
    assert res["relay_key"] == secret
    zip_bytes = captured["put"]
    assert isinstance(zip_bytes, bytes) and zip_bytes
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        source = z.read("relay.js").decode("utf-8")
    assert f'"{secret}"' in source


def test_netlify_zip_helper_includes_the_key():
    import io
    import zipfile
    zip_bytes, digest = _build_netlify_zip("mykey")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        source = z.read("relay.js").decode("utf-8")
    assert '"mykey"' in source
    assert digest


# --------------------------------------------------------------------------- #
# manager
# --------------------------------------------------------------------------- #

def test_manager_stores_and_returns_the_key(tmp_path: Path):
    mgr = RelayManager(data_dir=tmp_path)
    entry = mgr.add_relay("cf", "https://cf.workers.dev", "cloudflare", key="k1")
    assert entry["key"] == "k1"
    assert mgr.get_relay_key("https://cf.workers.dev") == "k1"
    assert mgr.get_relay_key("https://other.workers.dev") == ""


def test_deploy_and_add_persists_the_key(tmp_path: Path, monkeypatch):
    mgr = RelayManager(data_dir=tmp_path)
    monkeypatch.setattr(
        "zcode_gateway.relay_manager.deploy_cloudflare",
        lambda **kwargs: {"ok": True, "name": "n", "type": "cloudflare",
                          "url": "https://n.workers.dev",
                          "relay_key": kwargs.get("relay_secret", "")},
    )
    res = mgr.deploy_and_add("cloudflare", {"accountId": "a", "apiToken": "t"})
    key = res["relay"]["key"]
    assert key
    assert mgr.get_relay_key("https://n.workers.dev") == key
    # the key survives a reload from disk
    mgr2 = RelayManager(data_dir=tmp_path)
    assert mgr2.get_relay_key("https://n.workers.dev") == key


# --------------------------------------------------------------------------- #
# ping
# --------------------------------------------------------------------------- #

def test_ping_relay_sends_the_key(monkeypatch):
    import requests
    captured = {}

    def mock_get(url, headers=None, timeout=None, verify=None):
        captured["headers"] = headers
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    monkeypatch.setattr(requests, "get", mock_get)
    res = ping_relay("https://my-relay.workers.dev", relay_key="k9")
    assert res["ok"] is True
    assert captured["headers"][RELAY_KEY_HEADER] == "k9"


def test_ping_relay_reports_a_rejected_key(monkeypatch):
    import requests

    def mock_get(url, headers=None, timeout=None, verify=None):
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "unauthorized"
        return resp

    monkeypatch.setattr(requests, "get", mock_get)
    res = ping_relay("https://my-relay.workers.dev", relay_key="wrong")
    assert res["ok"] is False
    assert res["status"] == 401
    assert "key" in res["error"]


# --------------------------------------------------------------------------- #
# gateway side
# --------------------------------------------------------------------------- #

class _FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._closed = False

    async def aclose(self):
        self._closed = True


@pytest.mark.asyncio
async def test_upstream_sends_the_relay_key(tmp_path: Path):
    mgr = RelayManager(data_dir=tmp_path)
    mgr.add_relay("cf", "https://cf.workers.dev", "cloudflare", key="secret-key")
    cfg = UpstreamConfig()
    client = UpstreamClient(cfg, relay_manager=mgr)

    seen = {}

    async def fake_send(req, stream=False):
        seen["headers"] = req.headers
        return _FakeResponse(200)

    client._client.send = fake_send
    await client.send({"authorization": "Bearer t"}, {"model": "GLM-5.3"}, stream=False)
    assert seen["headers"][RELAY_KEY_HEADER] == "secret-key"
    await client.aclose()


@pytest.mark.asyncio
async def test_upstream_omits_the_key_when_the_relay_has_none(tmp_path: Path):
    mgr = RelayManager(data_dir=tmp_path)
    mgr.add_relay("cf", "https://cf.workers.dev", "cloudflare")
    cfg = UpstreamConfig()
    client = UpstreamClient(cfg, relay_manager=mgr)

    seen = {}

    async def fake_send(req, stream=False):
        seen["headers"] = req.headers
        return _FakeResponse(200)

    client._client.send = fake_send
    await client.send({"authorization": "Bearer t"}, {"model": "GLM-5.3"}, stream=False)
    assert RELAY_KEY_HEADER not in seen["headers"]
    await client.aclose()


@pytest.mark.asyncio
async def test_relay_401_is_a_transport_error_not_an_account_kill(tmp_path: Path):
    """A relay rejecting our key must not look like a revoked ZCode token."""
    mgr = RelayManager(data_dir=tmp_path)
    mgr.add_relay("cf", "https://cf.workers.dev", "cloudflare", key="secret-key")
    cfg = UpstreamConfig()
    client = UpstreamClient(cfg, relay_manager=mgr)

    async def fake_send(req, stream=False):
        return _FakeResponse(401, {"x-relay-error": "unauthorized"})

    client._client.send = fake_send
    with pytest.raises(TransportError):
        await client.send({"authorization": "Bearer t"}, {"model": "GLM-5.3"}, stream=False)
    await client.aclose()
