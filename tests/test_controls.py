"""The controls must hold no matter what the UI shows."""
import time

import pytest

from meridian import db as dbm
from meridian.rbac import Controls


def as_(conn, uid):
    return Controls(conn, uid)


def audit_count(conn, outcome):
    return conn.execute("SELECT COUNT(*) FROM audit WHERE outcome=?", (outcome,)).fetchone()[0]


# ---- RBAC ---------------------------------------------------------------
def test_developer_cannot_deploy_to_production(conn):
    ok, msg = as_(conn, "u3").perform("deploy", "REL-26.10")
    assert not ok and "Deploy to Production" in msg


def test_blocked_attempts_are_audited(conn):
    before = audit_count(conn, "denied")
    as_(conn, "u1").perform("approve_change", "CHG0030412")
    assert audit_count(conn, "denied") == before + 1


def test_expired_role_grants_nothing(conn):
    assert as_(conn, "u2").can("change.approve")
    conn.execute("UPDATE assignments SET expires=? WHERE uid='u2' AND role='cab'", (time.time() - 1,))
    assert not as_(conn, "u2").can("change.approve")


# ---- Change management --------------------------------------------------
def test_cannot_vote_twice(conn):
    ok, msg = as_(conn, "u4").perform("approve_change", "CHG0030412")
    assert not ok and "already voted" in msg


def test_cannot_assess_own_change(conn):
    elena = as_(conn, "u4")
    ok, msg = elena.create_change("Tune alert thresholds", "Normal", "Low", "u3", "")
    cid = msg.split()[0]
    assert elena.perform("submit_change", cid)[0]
    ok, msg = elena.perform("send_cab", cid)
    assert not ok and "you raised this change" in msg


def test_second_vote_schedules_normal_change(conn):
    assert as_(conn, "u6").perform("approve_change", "CHG0030412")[0]
    assert as_(conn, "u6").change("CHG0030412")["state"] == "Scheduled"


def test_rejection_fails_the_release_gate(conn):
    assert as_(conn, "u6").perform("reject_change", "CHG0030412")[0]
    ctl = as_(conn, "u5")
    assert ctl.gate_state(ctl.release("REL-26.10"), "cab") == "fail"


# ---- Release management -------------------------------------------------
def test_full_release_to_production(conn):
    assert as_(conn, "u6").perform("approve_change", "CHG0030412")[0]
    david = as_(conn, "u5")
    ok, msg = david.perform("deploy", "REL-26.10")
    assert not ok and "Rollback" in msg
    assert david.perform("sign_gate", "REL-26.10|rollback")[0]
    assert david.perform("deploy", "REL-26.10")[0]
    assert david.release("REL-26.10")["stage"] == 4
    assert david.change("CHG0030412")["state"] == "Review"


def test_failed_security_scan_blocks_promotion(conn):
    ok, msg = as_(conn, "u3").perform("promote", "REL-26.11")
    assert not ok and "Security scan" in msg


def test_freeze_blocks_production_deploy(conn):
    assert as_(conn, "u4").perform("freeze")[0]
    assert as_(conn, "u6").perform("approve_change", "CHG0030412")[0]
    david = as_(conn, "u5")
    david.perform("sign_gate", "REL-26.10|rollback")
    ok, msg = david.perform("deploy", "REL-26.10")
    assert not ok and "freeze" in msg


def test_builder_cannot_deploy_even_after_gaining_release_role(conn):
    # Tom approves Raj's toxic request as an exception...
    ok, _ = as_(conn, "u7").perform("approve_access", "RITM0010051")
    assert ok
    row = conn.execute("SELECT exception FROM access_requests WHERE id='RITM0010051'").fetchone()
    assert row["exception"] == 1
    # ...but build != deploy still stops Raj shipping his own release.
    assert as_(conn, "u6").perform("approve_change", "CHG0030412")[0]
    as_(conn, "u5").perform("sign_gate", "REL-26.10|rollback")
    ok, msg = as_(conn, "u3").perform("deploy", "REL-26.10")
    assert not ok and "you built this release" in msg


# ---- Identity & access --------------------------------------------------
def test_no_self_approval_of_access(conn):
    tom = as_(conn, "u7")
    ok, msg = tom.request_access("cab", 14, "Cover CAB")
    rid = msg.split()[0]
    ok, msg = tom.perform("approve_access", rid)
    assert not ok and "your own" in msg


def test_last_admin_cannot_be_revoked(conn):
    admin_row = conn.execute("SELECT id FROM assignments WHERE role='admin'").fetchone()["id"]
    # Give Sofia access.review so someone other than Tom can try.
    conn.execute("INSERT INTO role_perms VALUES ('cab','access.review')")
    ok, msg = as_(conn, "u6").perform("revoke", str(admin_row))
    assert not ok and "At least one" in msg


def test_admin_keeps_role_editing(conn):
    ok, msg = as_(conn, "u7").perform("perm", "admin|admin.roles")
    assert not ok and "Locked" in msg


def test_audit_log_is_append_only(conn):
    for sql in ("UPDATE audit SET outcome='allowed'", "DELETE FROM audit"):
        with pytest.raises(Exception, match="append-only"):
            conn.execute(sql)
        conn.rollback()


# ---- HTTP layer ---------------------------------------------------------
def test_forged_post_is_blocked_server_side(client):
    app, c = client
    c.post("/login", data={"uid": "u1"})
    r = c.post("/act/deploy", data={"target": "REL-26.10", "next": "/releases"})
    assert r.status_code == 302
    with dbm.connect(app.config["DB_URL"]) as conn:
        assert conn.execute("SELECT stage FROM releases WHERE id='REL-26.10'").fetchone()[0] == 3


def test_protected_pages_return_403(client):
    _, c = client
    c.post("/login", data={"uid": "u1"})
    assert c.get("/review").status_code == 403
    assert c.get("/audit").status_code == 403


@pytest.mark.parametrize("path", ["/", "/incidents", "/changes", "/releases", "/access", "/roles",
                                  "/changes?new=1", "/incidents?new=1"])
@pytest.mark.parametrize("uid", ["u1", "u2", "u3", "u4", "u5", "u6", "u7"])
def test_every_page_renders_for_every_user(client, path, uid):
    _, c = client
    c.post("/login", data={"uid": uid})
    assert c.get(path).status_code == 200


def test_open_redirect_is_refused(client):
    _, c = client
    r = c.post("/login", data={"uid": "u2", "next": "//evil.example"})
    assert r.headers["Location"].endswith("/")
