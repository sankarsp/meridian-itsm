"""REST API: same controls as the web UI, over bearer tokens."""
import pytest

from meridian import db as dbm
from meridian import tokens


@pytest.fixture
def api(client):
    app, c = client

    def token_for(uid):
        with dbm.connect(app.config["DB_URL"]) as conn:
            return tokens.create(conn, uid, "test")

    toks = {}

    def call(method, path, uid=None, **kw):
        headers = kw.pop("headers", {})
        if uid:
            toks.setdefault(uid, token_for(uid))
            headers["Authorization"] = f"Bearer {toks[uid]}"
        return c.open(f"/api/v1{path}", method=method, headers=headers, **kw)

    call.app = app
    return call


def test_requires_token(api):
    assert api("GET", "/me").status_code == 401
    r = api("GET", "/me", headers={"Authorization": "Bearer mrd_nope"})
    assert r.status_code == 401


def test_me_lists_roles_and_permissions(api):
    body = api("GET", "/me", "u5").get_json()
    assert body["roles"] == ["release_mgr"]
    assert "release.deploy" in body["permissions"]


def test_developer_deploy_is_forbidden_and_audited(api):
    r = api("POST", "/actions/deploy", "u3", json={"target": "REL-26.10"})
    assert r.status_code == 403 and r.get_json()["error"] == "forbidden"
    last = api("GET", "/audit?limit=1&outcome=denied", "u5").get_json()[0]
    assert last["uid"] == "u3" and last["channel"] == "api" and last["record"] == "REL-26.10"


def test_release_flow_over_api(api):
    r = api("POST", "/actions/deploy", "u5", json={"target": "REL-26.10"})
    assert r.status_code == 409 and r.get_json()["error"] == "blocked_by_control"
    assert api("POST", "/actions/approve_change", "u6", json={"target": "CHG0030412"}).status_code == 200
    assert api("POST", "/actions/sign_gate", "u5", json={"target": "REL-26.10|rollback"}).status_code == 200
    assert api("POST", "/actions/deploy", "u5", json={"target": "REL-26.10"}).status_code == 200
    rel = api("GET", "/releases/REL-26.10", "u1").get_json()
    assert rel["stage_name"] == "Production"
    assert api("GET", "/changes/CHG0030412", "u1").get_json()["state"] == "Review"


def test_ci_webhook_reports_scan_result(api):
    r = api("POST", "/releases/REL-26.11/gates/sec", "u5", json={"status": "pass", "note": "0 high findings"})
    assert r.status_code == 200 and r.get_json()["gates"]["sec"]["status"] == "pass"
    # Pipelines can't sign off human gates.
    r = api("POST", "/releases/REL-26.11/gates/uat", "u5", json={"status": "pass"})
    assert r.status_code == 409
    # And someone without release.gate can't report at all.
    assert api("POST", "/releases/REL-26.11/gates/sec", "u1", json={"status": "fail"}).status_code == 403


def test_create_records(api):
    r = api("POST", "/incidents", "u1", json={"description": "Card declines spiking in APAC", "priority": 2})
    assert r.status_code == 201 and r.get_json()["state"] == "New"
    assert api("POST", "/incidents", "u1", json={"description": ""}).status_code == 400
    r = api("POST", "/changes", "u3", json={"title": "Raise auth pool", "type": "Normal", "risk": "Low"})
    assert r.status_code == 201 and r.get_json()["approvals_required"] == 2
    assert api("POST", "/changes", "u1", json={"title": "x"}).status_code == 403
    r = api("POST", "/access-requests", "u1", json={"role": "cab", "days": 14, "justification": "Q4 CAB cover"})
    assert r.status_code == 201


def test_self_approval_blocked_over_api(api):
    rid = api("POST", "/access-requests", "u7", json={"role": "cab", "days": 14, "justification": "x"}).get_json()["id"]
    r = api("POST", "/actions/approve_access", "u7", json={"target": rid})
    assert r.status_code == 409 and "own" in r.get_json()["message"]


def test_action_catalog_explains_blocks(api):
    items = {a["key"]: a for a in api("GET", "/actions?target=REL-26.10", "u3").get_json()}
    assert items["deploy"]["allowed"] is False
    assert "Deploy to Production" in items["deploy"]["reason"]


def test_unknown_things_404(api):
    assert api("POST", "/actions/launch_missiles", "u7", json={}).status_code == 404
    assert api("GET", "/changes/CHG9999999", "u7").status_code == 404
    assert api("POST", "/actions/approve_change", "u6", json={"target": "CHG9999999"}).status_code == 404


def test_protected_reads(api):
    assert api("GET", "/audit", "u1").status_code == 403
    assert api("GET", "/assignments", "u1").status_code == 403
    assert api("GET", "/assignments", "u7").status_code == 200


def test_revoked_token_stops_working(api):
    with dbm.connect(api.app.config["DB_URL"]) as conn:
        tok = tokens.create(conn, "u5", "temp")
        tid = conn.execute("SELECT id FROM api_tokens WHERE name='temp'").fetchone()[0]
    ok = api("GET", "/me", headers={"Authorization": f"Bearer {tok}"})
    assert ok.status_code == 200
    with dbm.connect(api.app.config["DB_URL"]) as conn:
        tokens.revoke(conn, tid)
    assert api("GET", "/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_tokens_are_stored_hashed(api):
    with dbm.connect(api.app.config["DB_URL"]) as conn:
        tok = tokens.create(conn, "u1", "h")
        stored = conn.execute("SELECT token_hash FROM api_tokens WHERE name='h'").fetchone()[0]
    assert tok not in stored and len(stored) == 64
