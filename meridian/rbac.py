"""Roles, permissions and the controls that govern every action.

All checks run on the server. The UI only *displays* the reason a button is
locked; posting the form anyway goes through the same check and is logged as a
blocked attempt.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

DAY = 86400

ROLES = {
    "requester": {"name": "Requester", "desc": "Business user. Logs incidents and requests access."},
    "agent": {"name": "Service Desk Agent", "desc": "Triages and resolves incidents."},
    "developer": {"name": "Developer", "desc": "Builds releases, implements changes, promotes to lower environments."},
    "change_mgr": {"name": "Change Manager", "desc": "Assesses changes, chairs CAB, authorizes emergency changes, owns the freeze calendar."},
    "release_mgr": {"name": "Release Manager", "desc": "Owns release gates and production deployment."},
    "cab": {"name": "CAB Member", "desc": "Votes on normal changes and signs off release gates."},
    "admin": {"name": "IAM Administrator", "desc": "Owns roles, approves access, runs access reviews."},
}

PERMS = [
    {"key": "incident.create", "label": "Log incidents", "group": "Incidents"},
    {"key": "incident.work", "label": "Assign & resolve incidents", "group": "Incidents"},
    {"key": "change.create", "label": "Raise change requests", "group": "Change"},
    {"key": "change.assess", "label": "Assess, schedule & close changes", "group": "Change"},
    {"key": "change.approve", "label": "Vote at CAB", "group": "Change"},
    {"key": "change.emergency", "label": "Authorize emergency changes (ECAB)", "group": "Change"},
    {"key": "change.implement", "label": "Implement changes", "group": "Change"},
    {"key": "release.promote", "label": "Promote to QA / UAT / Staging", "group": "Release"},
    {"key": "release.gate", "label": "Sign off release gates", "group": "Release"},
    {"key": "release.deploy", "label": "Deploy to Production", "group": "Release"},
    {"key": "access.request", "label": "Request access", "group": "Access"},
    {"key": "access.approve", "label": "Approve access requests", "group": "Access"},
    {"key": "access.review", "label": "Run access certification", "group": "Access"},
    {"key": "freeze.manage", "label": "Manage change freeze", "group": "Governance"},
    {"key": "audit.view", "label": "View audit log", "group": "Governance"},
    {"key": "admin.roles", "label": "Edit role permissions", "group": "Governance"},
]
PERM_LABEL = {p["key"]: p["label"] for p in PERMS}

DEFAULT_ROLE_PERMS = {
    "requester": ["incident.create", "access.request"],
    "agent": ["incident.create", "incident.work", "change.create", "access.request"],
    "developer": ["incident.create", "change.create", "change.implement", "release.promote", "access.request"],
    "change_mgr": ["incident.create", "change.create", "change.assess", "change.approve", "change.emergency",
                   "freeze.manage", "audit.view", "access.request"],
    "release_mgr": ["incident.create", "release.promote", "release.gate", "release.deploy", "audit.view", "access.request"],
    "cab": ["incident.create", "change.approve", "release.gate", "audit.view", "access.request"],
    "admin": ["incident.create", "access.request", "access.approve", "access.review", "freeze.manage",
              "audit.view", "admin.roles"],
}

# Role pairs one person should not hold together.
TOXIC = [
    ("developer", "release_mgr", "Could build code and deploy it to production alone"),
    ("developer", "cab", "Could vote to approve their own changes"),
    ("admin", "release_mgr", "Could grant themselves deploy rights and ship"),
]

STAGES = ["Dev", "QA", "UAT", "Staging", "Production"]
GATES = {
    "build": "Build & unit tests",
    "sec": "Security scan",
    "uat": "UAT sign-off",
    "cab": "Change authorized",
    "rollback": "Rollback plan reviewed",
}
AUTO_GATES = {"build": "CI", "sec": "SAST/DAST"}
REQUIRED_GATES = {
    1: ["build"],
    2: ["build", "sec"],
    3: ["build", "sec", "uat"],
    4: ["build", "sec", "uat", "cab", "rollback"],
}
CHANGE_FLOW = ["New", "Assess", "Authorize", "Scheduled", "Implement", "Review", "Closed"]
AUTHORIZED_STATES = {"Scheduled", "Implement", "Review", "Closed"}
REQUIRED_VOTES = {"Standard": 0, "Normal": 2, "Emergency": 1}
CHANGE_TYPES = list(REQUIRED_VOTES)
RISKS = ["Low", "Moderate", "High"]
ACCESS_DURATIONS = [14, 30, 90]


def toxic_for(roles):
    return [t for t in TOXIC if t[0] in roles and t[1] in roles]


# --------------------------------------------------------------------------
# Action registry
# --------------------------------------------------------------------------
@dataclass
class Action:
    label: str
    perm: str
    run: Callable
    check: Optional[Callable] = None
    label_fn: Optional[Callable] = None


ACTIONS: dict[str, Action] = {}


def action(key, label, perm, check=None, label_fn=None):
    def deco(fn):
        ACTIONS[key] = Action(label, perm, fn, check, label_fn)
        return fn
    return deco


class Controls:
    """Everything one signed-in user is allowed to see and do."""

    def __init__(self, db, me: str, channel: str = "web"):
        self.db = db
        self.me = me
        self.channel = channel  # "web" or "api", recorded in the audit log

    # ---- identity -------------------------------------------------------
    def name(self, uid):
        row = self.db.execute("SELECT name FROM users WHERE id=?", (uid,)).fetchone()
        return row["name"] if row else (uid or "—")

    def roles_of(self, uid=None):
        uid = uid or self.me
        rows = self.db.execute(
            "SELECT role FROM assignments WHERE uid=? AND (expires IS NULL OR expires>?) ORDER BY id",
            (uid, time.time()),
        ).fetchall()
        out = []
        for r in rows:
            if r["role"] not in out:
                out.append(r["role"])
        return out

    def role_perms(self, role):
        return {r["perm"] for r in self.db.execute("SELECT perm FROM role_perms WHERE role=?", (role,))}

    def perms_of(self, uid=None):
        perms = set()
        for r in self.roles_of(uid):
            perms |= self.role_perms(r)
        return perms

    def can(self, perm, uid=None):
        return perm in self.perms_of(uid)

    def need(self, perm):
        if self.can(perm):
            return None
        names = ", ".join(ROLES[r]["name"] for r in self.roles_of()) or "none"
        return f"Needs “{PERM_LABEL[perm]}” permission. Your roles: {names}."

    def freeze_active(self):
        row = self.db.execute("SELECT value FROM settings WHERE key='freeze'").fetchone()
        return bool(row and row["value"] == "1")

    # ---- records --------------------------------------------------------
    def _one(self, sql, args, what):
        row = self.db.execute(sql, args).fetchone()
        if row is None:
            raise LookupError(f"{what} not found")
        return row

    def incident(self, iid):
        return self._one("SELECT * FROM incidents WHERE id=?", (iid,), "Incident")

    def change(self, cid):
        return self._one("SELECT * FROM changes WHERE id=?", (cid,), "Change")

    def votes(self, cid):
        return self.db.execute("SELECT * FROM votes WHERE change_id=? ORDER BY at", (cid,)).fetchall()

    def release(self, rid):
        return self._one("SELECT * FROM releases WHERE id=?", (rid,), "Release")

    def access_request(self, aid):
        return self._one("SELECT * FROM access_requests WHERE id=?", (aid,), "Access request")

    def assignment(self, aid):
        return self._one("SELECT * FROM assignments WHERE id=?", (int(aid),), "Assignment")

    def gate(self, rid, gate):
        return self.db.execute("SELECT * FROM gates WHERE release_id=? AND gate=?", (rid, gate)).fetchone()

    def gate_state(self, rel, gate):
        if gate == "cab":
            if not rel["change_id"]:
                return "pending"
            c = self.db.execute("SELECT state FROM changes WHERE id=?", (rel["change_id"],)).fetchone()
            if c is None:
                return "pending"
            if c["state"] == "Rejected":
                return "fail"
            return "pass" if c["state"] in AUTHORIZED_STATES else "pending"
        row = self.gate(rel["id"], gate)
        return row["status"] if row else "pending"

    def missing_gates(self, rel, stage):
        return [g for g in REQUIRED_GATES[stage] if self.gate_state(rel, g) != "pass"]

    # ---- action plumbing -----------------------------------------------
    def reason(self, key, target=None):
        """Why the signed-in user can't do this, or None if they can."""
        a = ACTIONS[key]
        why = self.need(a.perm)
        if why:
            return why
        if a.check:
            try:
                return a.check(self, target)
            except (LookupError, ValueError, TypeError, AttributeError):
                return "That record does not exist."
        return None

    def label(self, key, target=None):
        a = ACTIONS[key]
        if a.label_fn:
            try:
                return a.label_fn(self, target)
            except (LookupError, ValueError, TypeError, AttributeError):
                pass
        return a.label

    def perform(self, key, target=None):
        """Run an action if allowed. Always writes an audit entry."""
        if key not in ACTIONS:
            raise KeyError(key)
        label = self.label(key, target)
        why = self.reason(key, target)
        record = {"perm": "Role matrix", "freeze": "Freeze calendar"}.get(key) or (
            str(target).split("|")[0] if target else None)
        if why:
            self.log(label, record, "denied", why)
            self.db.commit()
            return False, why
        if key == "perm":
            role, perm = target.split("|")
            label = f"{'Revoked' if perm in self.role_perms(role) else 'Granted'} {perm} on {ROLES[role]['name']}"
        ACTIONS[key].run(self, target)
        self.log(label, record, "allowed")
        self.db.commit()
        return True, label

    def log(self, action_label, record, outcome, detail=None):
        roles = ", ".join(ROLES[r]["name"] for r in self.roles_of())
        self.db.execute(
            "INSERT INTO audit(at, uid, roles, action, record, outcome, detail, channel) VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), self.me, roles, action_label, record, outcome, detail, self.channel),
        )

    # ---- CI / pipeline integration -------------------------------------
    def report_gate(self, rid, gate, status, note=None):
        """Record an automated check result (build or security scan) from a pipeline."""
        label = f"Pipeline result: {GATES.get(gate, gate)} {status}"
        why = self.need("release.gate")
        if not why:
            try:
                r = self.release(rid)
            except LookupError:
                return False, "That release does not exist."
            if gate not in AUTO_GATES:
                why = "Only automated checks (build, sec) can be reported by a pipeline."
            elif status not in ("pass", "fail"):
                why = "Status must be pass or fail."
            elif r["stage"] >= 4:
                why = "This release is already live."
        if why:
            self.log(label, rid, "denied", why)
            self.db.commit()
            return False, why
        self.db.execute("UPDATE gates SET status=?, signed_by=?, note=? WHERE release_id=? AND gate=?",
                        (status, AUTO_GATES[gate], (note or "")[:200] or None, rid, gate))
        self.log(label, rid, "allowed", note)
        self.db.commit()
        return True, label

    # ---- create forms ---------------------------------------------------
    def _next_id(self, table, prefix, start):
        row = self.db.execute(f"SELECT id FROM {table} WHERE id LIKE ? ORDER BY id DESC LIMIT 1", (prefix + "%",)).fetchone()
        n = int(row["id"][len(prefix):]) + 1 if row else start
        return f"{prefix}{n:07d}"

    def _deny_create(self, label, perm):
        why = self.need(perm)
        if why:
            self.log(label, None, "denied", why)
            self.db.commit()
        return why

    def create_incident(self, descr, priority):
        why = self._deny_create("Log incident", "incident.create")
        if why:
            return False, why
        descr = (descr or "").strip()
        if not descr:
            return False, "Add a short description."
        if priority not in (1, 2, 3, 4):
            return False, "Priority must be P1 to P4."
        iid = self._next_id("incidents", "INC", 41200)
        self.db.execute(
            "INSERT INTO incidents(id, descr, priority, state, caller, assignee, opened) VALUES (?,?,?,?,?,?,?)",
            (iid, descr, priority, "New", self.me, None, time.time()))
        self.log("Logged incident", iid, "allowed")
        self.db.commit()
        return True, f"{iid} logged"

    def create_change(self, title, ctype, risk, implementer, window):
        why = self._deny_create("Raise change", "change.create")
        if why:
            return False, why
        title = (title or "").strip()
        if not title:
            return False, "Add a change title."
        if ctype not in CHANGE_TYPES or risk not in RISKS:
            return False, "Choose a valid type and risk."
        if not self.db.execute("SELECT 1 FROM users WHERE id=?", (implementer,)).fetchone():
            return False, "Choose an implementer."
        cid = self._next_id("changes", "CHG", 30420)
        self.db.execute(
            "INSERT INTO changes(id, title, type, risk, state, requested_by, implementer, win, release_id) "
            "VALUES (?,?,?,?,?,?,?,?,NULL)",
            (cid, title, ctype, risk, "New", self.me, implementer, (window or "").strip()))
        self.log("Raised change", cid, "allowed")
        self.db.commit()
        return True, f"{cid} created"

    def request_access(self, role, days, why_text):
        why = self._deny_create("Request access", "access.request")
        if why:
            return False, why
        if role not in ROLES:
            return False, "Choose a role."
        if role in self.roles_of():
            return False, f"You already hold {ROLES[role]['name']}."
        if days not in ACCESS_DURATIONS:
            return False, "Choose 14, 30 or 90 days."
        why_text = (why_text or "").strip()
        if not why_text:
            return False, "Add a business justification."
        rid = self._next_id("access_requests", "RITM", 10060)
        self.db.execute(
            "INSERT INTO access_requests(id, uid, role, days, why, state, requested, decided_by, exception) "
            "VALUES (?,?,?,?,?,?,?,NULL,0)",
            (rid, self.me, role, days, why_text, "Pending", time.time()))
        self.log(f"Requested {ROLES[role]['name']} role", rid, "allowed")
        self.db.commit()
        return True, f"{rid} submitted for approval"


# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------
def _assign_chk(ctl, t):
    if ctl.incident(t)["state"] != "New":
        return "Only new incidents can be assigned."


@action("assign_inc", "Assign to me", "incident.work", check=_assign_chk)
def _assign_run(ctl, t):
    ctl.db.execute("UPDATE incidents SET assignee=?, state='In Progress' WHERE id=?", (ctl.me, t))


def _resolve_chk(ctl, t):
    i = ctl.incident(t)
    if i["state"] == "Resolved":
        return "This incident is already resolved."
    if i["assignee"] and i["assignee"] != ctl.me:
        return f"Assigned to {ctl.name(i['assignee'])}. Only the assignee can resolve."


@action("resolve_inc", "Resolve incident", "incident.work", check=_resolve_chk)
def _resolve_run(ctl, t):
    ctl.db.execute("UPDATE incidents SET state='Resolved', assignee=COALESCE(assignee, ?) WHERE id=?", (ctl.me, t))


# --------------------------------------------------------------------------
# Change management
# --------------------------------------------------------------------------
def _in_state(c, state):
    if c["state"] != state:
        return f"This change is in {c['state']}, not {state}."


def _set_change(ctl, cid, state):
    ctl.db.execute("UPDATE changes SET state=? WHERE id=?", (state, cid))


def _submit_chk(ctl, t):
    c = ctl.change(t)
    if (w := _in_state(c, "New")):
        return w
    if c["requested_by"] != ctl.me and not ctl.can("change.assess"):
        return "Only the requester or a Change Manager can submit this change."


@action("submit_change", "Submit for assessment", "change.create", check=_submit_chk)
def _submit_run(ctl, t):
    _set_change(ctl, t, "Assess")


def _assess_chk(ctl, t):
    c = ctl.change(t)
    if (w := _in_state(c, "Assess")):
        return w
    if c["requested_by"] == ctl.me:
        return "Segregation of duties: you raised this change, so you cannot assess it."


@action("send_cab", "Send to CAB", "change.assess", check=_assess_chk,
        label_fn=lambda ctl, t: "Schedule (pre-approved)" if ctl.change(t)["type"] == "Standard" else "Send to CAB")
def _send_cab_run(ctl, t):
    _set_change(ctl, t, "Scheduled" if ctl.change(t)["type"] == "Standard" else "Authorize")


def _vote_chk(ctl, t):
    c = ctl.change(t)
    if c["state"] != "Authorize":
        return "This change is not awaiting CAB."
    if c["requested_by"] == ctl.me:
        return "Segregation of duties: you raised this change."
    if c["implementer"] == ctl.me:
        return "Segregation of duties: you are implementing this change."
    if any(v["uid"] == ctl.me for v in ctl.votes(t)):
        return "You have already voted on this change."
    if c["type"] == "Emergency" and not ctl.can("change.emergency"):
        return "Emergency changes are authorized by a Change Manager (ECAB)."


def _record_vote(ctl, t, decision):
    ctl.db.execute("INSERT INTO votes(change_id, uid, decision, at) VALUES (?,?,?,?)", (t, ctl.me, decision, time.time()))
    c = ctl.change(t)
    if decision == "rejected":
        _set_change(ctl, t, "Rejected")
        return
    approvals = sum(1 for v in ctl.votes(t) if v["decision"] == "approved")
    if approvals >= REQUIRED_VOTES[c["type"]]:
        _set_change(ctl, t, "Scheduled")


@action("approve_change", "CAB vote: approve", "change.approve", check=_vote_chk)
def _approve_run(ctl, t):
    _record_vote(ctl, t, "approved")


@action("reject_change", "CAB vote: reject", "change.approve", check=_vote_chk)
def _reject_run(ctl, t):
    _record_vote(ctl, t, "rejected")


def _start_chk(ctl, t):
    c = ctl.change(t)
    if (w := _in_state(c, "Scheduled")):
        return w
    if c["implementer"] != ctl.me:
        return f"Only the assigned implementer ({ctl.name(c['implementer'])}) can start this change."
    if ctl.freeze_active() and c["type"] != "Emergency":
        return "Change freeze is active. Only emergency changes can be implemented."
    if c["release_id"]:
        return f"This change ships through release {c['release_id']}. Deploy it from Releases."


@action("start_impl", "Start implementation", "change.implement", check=_start_chk)
def _start_run(ctl, t):
    _set_change(ctl, t, "Implement")


def _complete_chk(ctl, t):
    c = ctl.change(t)
    if (w := _in_state(c, "Implement")):
        return w
    if c["implementer"] != ctl.me:
        return f"Only {ctl.name(c['implementer'])} can complete this change."


@action("complete_impl", "Mark implemented", "change.implement", check=_complete_chk)
def _complete_run(ctl, t):
    _set_change(ctl, t, "Review")


@action("close_change", "Close change", "change.assess", check=lambda ctl, t: _in_state(ctl.change(t), "Review"))
def _close_run(ctl, t):
    _set_change(ctl, t, "Closed")


# --------------------------------------------------------------------------
# Release management
# --------------------------------------------------------------------------
def _gate_names(gates):
    return ", ".join(GATES[g] for g in gates)


def _promote_chk(ctl, t):
    r = ctl.release(t)
    if r["stage"] == 3:
        return "The last step is Deploy to Production."
    if r["stage"] >= 4:
        return "This release is already live."
    missing = ctl.missing_gates(r, r["stage"] + 1)
    if missing:
        return f"Gate not met for {STAGES[r['stage'] + 1]}: {_gate_names(missing)}."


@action("promote", "Promote release", "release.promote", check=_promote_chk,
        label_fn=lambda ctl, t: f"Promote to {STAGES[ctl.release(t)['stage'] + 1]}")
def _promote_run(ctl, t):
    ctl.db.execute("UPDATE releases SET stage=stage+1 WHERE id=?", (t,))


def _deploy_chk(ctl, t):
    r = ctl.release(t)
    if r["stage"] != 3:
        return "Only releases in Staging can be deployed to Production."
    if r["built_by"] == ctl.me:
        return "Segregation of duties: you built this release, so someone else must deploy it."
    missing = ctl.missing_gates(r, 4)
    if missing:
        return f"Gate not met: {_gate_names(missing)}."
    if ctl.freeze_active():
        c = ctl.db.execute("SELECT type FROM changes WHERE id=?", (r["change_id"],)).fetchone()
        if not c or c["type"] != "Emergency":
            return "Change freeze is active. Production deploys need an emergency change."


@action("deploy", "Deploy to Production", "release.deploy", check=_deploy_chk)
def _deploy_run(ctl, t):
    r = ctl.release(t)
    ctl.db.execute("UPDATE releases SET stage=4 WHERE id=?", (t,))
    if r["change_id"]:
        ctl.db.execute("UPDATE changes SET state='Review' WHERE id=? AND state!='Closed'", (r["change_id"],))


def _split_gate(t):
    rid, gate = t.split("|")
    if gate not in GATES or gate == "cab":
        raise LookupError("gate")
    return rid, gate


def _sign_chk(ctl, t):
    rid, gate = _split_gate(t)
    r = ctl.release(rid)
    if gate in AUTO_GATES:
        return "Automated checks can't be signed off by hand. Re-run them instead."
    if r["stage"] >= 4:
        return "This release is already live."
    if r["built_by"] == ctl.me:
        return "Segregation of duties: you built this release."
    if ctl.gate_state(r, gate) == "pass":
        return "This gate is already signed off."


@action("sign_gate", "Sign off gate", "release.gate", check=_sign_chk,
        label_fn=lambda ctl, t: f"Sign off {GATES[_split_gate(t)[1]].lower()}")
def _sign_run(ctl, t):
    rid, gate = _split_gate(t)
    ctl.db.execute("UPDATE gates SET status='pass', signed_by=?, note=NULL WHERE release_id=? AND gate=?", (ctl.me, rid, gate))


def _rerun_chk(ctl, t):
    rid, gate = _split_gate(t)
    r = ctl.release(rid)
    if gate not in AUTO_GATES:
        return "Only automated checks can be re-run."
    if ctl.gate_state(r, gate) == "pass":
        return "This check already passed."


@action("rerun", "Re-run automated check", "release.gate", check=_rerun_chk)
def _rerun_run(ctl, t):
    rid, gate = _split_gate(t)
    # Demo stand-in for triggering the real pipeline job.
    ctl.db.execute("UPDATE gates SET status='pass', signed_by=?, note='Re-run passed' WHERE release_id=? AND gate=?",
                   (AUTO_GATES[gate], rid, gate))


# --------------------------------------------------------------------------
# Identity & access
# --------------------------------------------------------------------------
def _ar_chk(ctl, t):
    r = ctl.access_request(t)
    if r["state"] != "Pending":
        return "This request has already been decided."
    if r["uid"] == ctl.me:
        return "You cannot approve your own access request."


def _ar_conflicts(ctl, t):
    r = ctl.access_request(t)
    return toxic_for(ctl.roles_of(r["uid"]) + [r["role"]])


@action("approve_access", "Approve access request", "access.approve", check=_ar_chk,
        label_fn=lambda ctl, t: "Approve with exception" if _ar_conflicts(ctl, t) else "Approve")
def _approve_access_run(ctl, t):
    r = ctl.access_request(t)
    exception = 1 if _ar_conflicts(ctl, t) else 0
    ctl.db.execute("UPDATE access_requests SET state='Approved', decided_by=?, exception=? WHERE id=?", (ctl.me, exception, t))
    ctl.db.execute("INSERT INTO assignments(uid, role, expires, certified) VALUES (?,?,?,NULL)",
                   (r["uid"], r["role"], time.time() + r["days"] * DAY))


@action("reject_access", "Reject access request", "access.approve", check=_ar_chk)
def _reject_access_run(ctl, t):
    ctl.db.execute("UPDATE access_requests SET state='Rejected', decided_by=? WHERE id=?", (ctl.me, t))


def _certify_chk(ctl, t):
    if ctl.assignment(t)["uid"] == ctl.me:
        return "You cannot certify your own access."


@action("certify", "Certify access", "access.review", check=_certify_chk)
def _certify_run(ctl, t):
    ctl.db.execute("UPDATE assignments SET certified=? WHERE id=?", (time.time(), int(t)))


def _revoke_chk(ctl, t):
    a = ctl.assignment(t)
    if a["uid"] == ctl.me:
        return "You cannot revoke your own access."
    if a["role"] == "admin":
        admins = ctl.db.execute("SELECT COUNT(*) FROM assignments WHERE role='admin'").fetchone()[0]
        if admins < 2:
            return "At least one IAM Administrator must remain."


@action("revoke", "Revoke access", "access.review", check=_revoke_chk)
def _revoke_run(ctl, t):
    ctl.db.execute("DELETE FROM assignments WHERE id=?", (int(t),))


# --------------------------------------------------------------------------
# Governance
# --------------------------------------------------------------------------
@action("freeze", "Toggle change freeze", "freeze.manage",
        label_fn=lambda ctl, t: "Lift freeze" if ctl.freeze_active() else "Start quarter-end freeze")
def _freeze_run(ctl, t):
    ctl.db.execute("UPDATE settings SET value=? WHERE key='freeze'", ("0" if ctl.freeze_active() else "1",))


def _perm_chk(ctl, t):
    role, perm = t.split("|")
    if role not in ROLES or perm not in PERM_LABEL:
        raise LookupError("perm")
    if role == "admin" and perm == "admin.roles":
        return "Locked: the IAM Administrator role must keep this permission."


@action("perm", "Edit role permission", "admin.roles", check=_perm_chk)
def _perm_run(ctl, t):
    role, perm = t.split("|")
    if perm in ctl.role_perms(role):
        ctl.db.execute("DELETE FROM role_perms WHERE role=? AND perm=?", (role, perm))
    else:
        ctl.db.execute("INSERT INTO role_perms(role, perm) VALUES (?,?)", (role, perm))
