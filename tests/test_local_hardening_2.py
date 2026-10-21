"""Regressions for the local-first hardening findings.

- a static shared secret in a public repo is a public secret: the
  `gateway-internal` sentinel must not authenticate anything.
- `verify=False` on a credential path is a MITM on the user's credentials.
- the upstream author's referral code and mail domain must not be the
  defaults a user inherits silently.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from zcode_gateway.app import create_app
from zcode_gateway.config import ClientKey, Config

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# 1. no static shared secret
# --------------------------------------------------------------------------- #

def _cfg(tmp_path) -> Config:
    cfg = Config()
    cfg.server.require_client_key = True
    cfg.server.admin_key = "adm-test"
    cfg.server.client_keys = [ClientKey(key="ck-test", name="t", rpm=0)]
    cfg.accounts.source = "pool_file"
    cfg.accounts.pool_file = str(tmp_path / "empty.json")
    (tmp_path / "empty.json").write_text('{"accounts": []}', encoding="utf-8")
    cfg.store.sqlite_path = str(tmp_path / "g.db")
    cfg.logging.capture_dir = str(tmp_path / "logs")
    return cfg


def test_legacy_internal_sentinel_is_gone():
    src = (REPO / "zcode_gateway" / "deps.py").read_text(encoding="utf-8")
    assert "gateway-internal" not in src
    assert "_LEGACY_INTERNAL" not in src
    # and nowhere else in the shipped source
    for path in _py_sources():
        assert "gateway-internal" not in path.read_text(encoding="utf-8"), \
            f"{path} still ships the static sentinel"


def test_static_sentinel_grants_no_admin(tmp_path):
    """The old sentinel must answer 403 on the admin API, not 200."""
    app = create_app(_cfg(tmp_path))
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        r = client.get("/admin/pool/state",
                       headers={"Authorization": "Bearer gateway-internal"})
        assert r.status_code == 403
        # the real per-install key still works
        ok = client.get("/admin/pool/state",
                        headers={"Authorization": "Bearer adm-test"})
        assert ok.status_code == 200


def test_per_process_internal_token_still_authenticates(tmp_path):
    app = create_app(_cfg(tmp_path))
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        token = app.state.app_state.internal_token
        assert token and token != "gateway-internal"
        r = client.get("/admin/pool/state",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# --------------------------------------------------------------------------- #
# 2. TLS verification on credential paths
# --------------------------------------------------------------------------- #

def _py_sources() -> list[Path]:
    return [p for p in REPO.rglob("*.py")
            if ".venv" not in p.parts and "tests" not in p.parts]


def test_no_verify_false_anywhere_in_the_source():
    offenders = []
    for path in _py_sources():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # `auto_verify = False` is a flag, not a TLS switch
            if "verify=False" in line or re.search(r"\bverify\s*=\s*False", line):
                offenders.append(f"{path.relative_to(REPO)}:{i}: {line.strip()}")
    assert not offenders, "TLS verification disabled:\n" + "\n".join(offenders)


def test_mail_session_verifies_tls():
    """The mailbox API carries the account password: it must verify."""
    src = (REPO / "generator" / "main.py").read_text(encoding="utf-8")
    assert "self.session.verify = self._verify" in src
    assert "certifi.where()" in src


# --------------------------------------------------------------------------- #
# 3. no author-favoring defaults
# --------------------------------------------------------------------------- #

def test_no_referral_code_or_domain_baked_in():
    """Nobody's referral code or mail domain may ship as a default."""
    patterns = ("MT9GNDQ8", "behnamrjd")
    for path in _py_sources() + list(REPO.glob("*.yaml")) + \
            list((REPO / "mail-worker").glob("*.json")) + \
            list((REPO / "mail-worker").glob("*.md")) + \
            list((REPO / "docs").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for pat in patterns:
            assert pat not in text, f"{path.relative_to(REPO)} still ships {pat}"


def test_config_defaults_have_no_referral_code():
    from zcode_gateway.config import GeneratorConfig
    assert GeneratorConfig().invite_code == ""


def test_generator_manager_defaults_have_no_referral_code(tmp_path):
    from zcode_gateway.generator import GeneratorManager
    mgr = GeneratorManager(Path(tmp_path), data_dir=Path(tmp_path))
    assert mgr.options()["invite_code"] == ""


def test_generator_config_has_no_default_domain():
    src = (REPO / "generator" / "config.py").read_text(encoding="utf-8")
    assert "'mail_domain': ''" in src
    assert "'invite_code': ''" in src


def test_signup_without_a_domain_fails_loudly():
    """No domain configured -> the signup must refuse, not use someone's."""
    import sys
    pytest.importorskip("playwright", reason="generator deps are optional")
    sys.path.insert(0, str(REPO / "generator"))
    try:
        import main as gen_main
    finally:
        sys.path.pop(0)

    import logging
    logger = logging.getLogger("test-no-domain")
    mail = gen_main.CatchAllMail(logger_instance=logger)
    # no ZAI_MAIL_DOMAIN, no config domain
    assert mail._pick_domain() == ""
    assert mail.create_account() is False
    assert mail.email is None
