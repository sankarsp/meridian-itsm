"""REST API (v1).

Authenticate with `Authorization: Bearer mrd_...`. Every call runs through the
same Controls object as the web UI, so permissions, segregation of duties,
freeze windows and gates are enforced identically, and every write (allowed
or blocked) lands in the audit log with channel="api".
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from . import db as dbm
from . import tokens
from .rbac import ACTIONS, AUTO_GATES, GATES, PERMS, REQUIRED_VOTES, ROLES, STAGES, Controls, toxic_for

bp = Blueprint("api", __name__, url_prefix="/api/v1")

TIME_FIELDS = {"opened", "at", "expires", "certified", "requested", "created", "last_used"}

# What each action's `target` looks like, for the action catalog.
TARGET_FORMAT = {
    "assign_inc": "incident id", "resolve_inc": "incident id",
    "submit_change": "change id", "send_cab": "change id", "approve_change": "change id",
    "reject_change": "change id", "start_impl": "change id", "complete_impl": "change id", "close_change": "change id",
    "promote": "release id", "deploy": "release id",
    "sign_gate": "release id|gate (uat or rollback)", "rerun": "release id|gate (build or sec)",
    "approve_access": "access request id", "reject_access": "access request id",
    "certify": "assignment id", "revoke": "assignment id",
    "freeze": "none", "perm": "role|permission",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ts else None


def out(row, drop=()):
    if row is None:
        return None
    return {k: (iso(v) if k in TIME_FIELDS else v) for k, v in dict(row).items() if k not in drop}


def error(status, code, message, **extra):
    return jsonify({"error": code, "message": message, **extra}), status


def body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def result(ok, msg, perm=None, kind="control", **extra):
    """Translate a Controls result into an HTTP response.

    403 forbidden         the caller lacks the permission
    404 not_found         the target record doesn't exist
    409 blocked_by_control a control stopped it (SoD, freeze, gate, workflow state)
    400 invalid           the request body failed validation
    """
    if ok:
        return jsonify({"ok": True, "message": msg, **extra})
    if perm and g.ctl.need(perm):
        return error(403, "forbidden", msg, **extra)
    if msg == "That record does not exist.":
        return error(404, "not_found", msg, **extra)
    if kind == "validation":
        return error(400, "invalid", msg, **extra)
    return error(409, "blocked_by_control", msg, **extra)


def change_json(c):
    d = out(c)
    votes = g.ctl.votes(c["id"])
    d["votes"] = [out(v, drop=("change_id",)) for v in votes]
    d["approvals_required"] = REQUIRED_VOTES[c["type"]]
    d["approvals"] = sum(1 for v in votes if v["decision"] == "approved")
    return d


def release_json(r):
    d = out(r, drop=("items",))
    d["stage_name"] = STAGES[r["stage"]]
    d["items"] = [i for i in (r["items"] or "").split("\n") if i]
    gates = {}
    for key, label in GATES.items():
        row = g.ctl.gate(r["id"], key) if key != "cab" else None
        gates[key] = {"label": label, "status": g.ctl.gate_state(r, key),
                      "signed_by": row["signed_by"] if row else None, "note": row["note"] if row else None,
                      "automated": key in AUTO_GATES}
    d["gates"] = gates
    if r["stage"] < 4:
        d["next_stage"] = STAGES[r["stage"] + 1]
        d["missing_gates"] = g.ctl.missing_gates(r, r["stage"] + 1)
    return d


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@bp.before_request
def authenticate():
    g.db = dbm.connect(current_app.config["DB_URL"])
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    uid = tokens.resolve(g.db, token)
    if not uid:
        return error(401, "unauthorized", "Send a valid API token as 'Authorization: Bearer <token>'.")
    g.me = uid
    g.ctl = Controls(g.db, uid, channel="api")


@bp.errorhandler(404)
def not_found(_e):
    return error(404, "not_found", "No such resource.")


@bp.errorhandler(405)
def bad_method(_e):
    return error(405, "method_not_allowed", "That method isn't supported here.")


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------
@bp.get("/me")
def me():
    c = g.ctl
    roles = c.roles_of()
    user = out(g.db.execute("SELECT * FROM users WHERE id=?", (g.me,)).fetchone())
    return jsonify({**user, "roles": roles, "permissions": sorted(c.perms_of()),
                    "sod_exceptions": [{"roles": [a, b], "risk": why} for a, b, why in toxic_for(roles)]})


@bp.get("/roles")
def roles():
    c = g.ctl
    return jsonify({
        "roles": [{"key": r, **ROLES[r], "permissions": sorted(c.role_perms(r))} for r in ROLES],
        "permissions": PERMS,
    })


@bp.get("/users")
def users():
    rows = g.db.execute("SELECT * FROM users ORDER BY id").fetchall()
    return jsonify([{**out(u), "roles": g.ctl.roles_of(u["id"])} for u in rows])


# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------
@bp.get("/incidents")
def list_incidents():
    sql, args = "SELECT * FROM incidents", []
    if request.args.get("state"):
        sql += " WHERE state=?"
        args.append(request.args["state"])
    return jsonify([out(i) for i in g.db.execute(sql + " ORDER BY opened DESC", args)])


@bp.post("/incidents")
def create_incident():
    b = body()
    try:
        pri = int(b.get("priority", 3))
    except (TypeError, ValueError):
        pri = 0
    ok, msg = g.ctl.create_incident(b.get("description"), pri)
    if not ok:
        return result(ok, msg, "incident.create", kind="validation")
    iid = msg.split()[0]
    return jsonify(out(g.ctl.incident(iid))), 201


@bp.get("/incidents/<iid>")
def get_incident(iid):
    try:
        return jsonify(out(g.ctl.incident(iid)))
    except LookupError:
        return error(404, "not_found", f"No incident {iid}.")


# --------------------------------------------------------------------------
# Changes
# --------------------------------------------------------------------------
@bp.get("/changes")
def list_changes():
    sql, args = "SELECT * FROM changes", []
    if request.args.get("state"):
        sql += " WHERE state=?"
        args.append(request.args["state"])
    return jsonify([change_json(c) for c in g.db.execute(sql + " ORDER BY id DESC", args).fetchall()])


@bp.post("/changes")
def create_change():
    b = body()
    ok, msg = g.ctl.create_change(b.get("title"), b.get("type", "Normal"), b.get("risk", "Moderate"),
                                  b.get("implementer", g.me), b.get("window"))
    if not ok:
        return result(ok, msg, "change.create", kind="validation")
    return jsonify(change_json(g.ctl.change(msg.split()[0]))), 201


@bp.get("/changes/<cid>")
def get_change(cid):
    try:
        return jsonify(change_json(g.ctl.change(cid)))
    except LookupError:
        return error(404, "not_found", f"No change {cid}.")


# --------------------------------------------------------------------------
# Releases
# --------------------------------------------------------------------------
@bp.get("/releases")
def list_releases():
    return jsonify([release_json(r) for r in g.db.execute("SELECT * FROM releases ORDER BY id DESC").fetchall()])


@bp.get("/releases/<rid>")
def get_release(rid):
    try:
        return jsonify(release_json(g.ctl.release(rid)))
    except LookupError:
        return error(404, "not_found", f"No release {rid}.")


@bp.post("/releases/<rid>/gates/<gate>")
def report_gate(rid, gate):
    """Webhook for CI/CD: report a build or security-scan result."""
    b = body()
    ok, msg = g.ctl.report_gate(rid, gate, b.get("status"), b.get("note"))
    if not ok:
        return result(ok, msg, "release.gate")
    return jsonify(release_json(g.ctl.release(rid)))


# --------------------------------------------------------------------------
# Access
# --------------------------------------------------------------------------
@bp.get("/access-requests")
def list_access_requests():
    rows = g.db.execute("SELECT * FROM access_requests ORDER BY requested DESC").fetchall()
    res = []
    for a in rows:
        d = out(a)
        d["exception"] = bool(a["exception"])
        d["sod_conflicts"] = [why for _, _, why in toxic_for(g.ctl.roles_of(a["uid"]) + [a["role"]])] \
            if a["state"] == "Pending" else []
        res.append(d)
    return jsonify(res)


@bp.post("/access-requests")
def create_access_request():
    b = body()
    try:
        days = int(b.get("days", 30))
    except (TypeError, ValueError):
        days = 0
    ok, msg = g.ctl.request_access(b.get("role"), days, b.get("justification"))
    if not ok:
        return result(ok, msg, "access.request", kind="validation")
    rid = msg.split()[0]
    return jsonify(out(g.ctl.access_request(rid))), 201


@bp.get("/assignments")
def list_assignments():
    if not g.ctl.can("access.review"):
        return error(403, "forbidden", g.ctl.need("access.review"))
    return jsonify([out(a) for a in g.db.execute("SELECT * FROM assignments ORDER BY uid, id")])


# --------------------------------------------------------------------------
# Governance
# --------------------------------------------------------------------------
@bp.get("/audit")
def audit():
    if not g.ctl.can("audit.view"):
        return error(403, "forbidden", g.ctl.need("audit.view"))
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    except ValueError:
        limit = 100
    sql, args = "SELECT * FROM audit", []
    if request.args.get("outcome") in ("allowed", "denied"):
        sql += " WHERE outcome=?"
        args.append(request.args["outcome"])
    rows = g.db.execute(sql + " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()
    return jsonify([out(r) for r in rows])


@bp.get("/settings/freeze")
def freeze_status():
    return jsonify({"active": g.ctl.freeze_active()})


# --------------------------------------------------------------------------
# Workflow actions
# --------------------------------------------------------------------------
@bp.get("/actions")
def list_actions():
    """Every workflow action, and whether the caller can run it right now for a given target."""
    target = request.args.get("target")
    res = []
    for key, a in ACTIONS.items():
        item = {"key": key, "label": a.label, "permission": a.perm, "target": TARGET_FORMAT.get(key, "id")}
        if target is not None or key == "freeze":
            why = g.ctl.reason(key, target or None)
            item["allowed"] = why is None
            item["reason"] = why
        else:
            item["has_permission"] = g.ctl.can(a.perm)
        res.append(item)
    return jsonify(res)


@bp.post("/actions/<key>")
def run_action(key):
    if key not in ACTIONS:
        return error(404, "not_found", f"No action '{key}'. GET /api/v1/actions lists them.")
    target = body().get("target")
    ok, msg = g.ctl.perform(key, str(target) if target is not None else None)
    return result(ok, msg, ACTIONS[key].perm, action=key, target=target)
