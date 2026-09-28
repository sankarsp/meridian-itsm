"""Meridian ITSM — Flask application."""
from __future__ import annotations

import os
import time
from contextlib import closing
from datetime import datetime

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape

from . import db as dbm
from . import tokens
from .rbac import (ACCESS_DURATIONS, AUTO_GATES, CHANGE_FLOW, CHANGE_TYPES, GATES, PERM_LABEL, PERMS,
                   REQUIRED_GATES, REQUIRED_VOTES, RISKS, ROLES, STAGES, TOXIC, Controls, toxic_for)

DEFAULT_USER = "u3"

PILL = {
    "pass": "p-ok", "fail": "p-bad", "pending": "p-mute",
    "Approved": "p-ok", "Rejected": "p-bad", "Pending": "p-warn",
    "New": "p-info", "Assess": "p-info", "Authorize": "p-warn", "Scheduled": "p-ok", "Implement": "p-warn",
    "Review": "p-info", "Closed": "p-mute", "In Progress": "p-warn", "Resolved": "p-ok",
    "allowed": "p-ok", "denied": "p-bad",
}


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        DB_URL=db_path or os.environ.get("DATABASE_URL") or os.environ.get("MERIDIAN_DB")
        or os.path.join(app.instance_path, "meridian.db"),
        DEMO_MODE=os.environ.get("MERIDIAN_DEMO", "1") == "1",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
    )
    if not dbm.is_postgres(app.config["DB_URL"]):
        os.makedirs(os.path.dirname(os.path.abspath(app.config["DB_URL"])), exist_ok=True)
    with closing(dbm.connect(app.config["DB_URL"])) as conn:
        dbm.init(conn)

    from .api import bp as api_bp
    app.register_blueprint(api_bp)
    _register_cli(app)

    # ------------------------------------------------------------------
    # Request lifecycle
    # ------------------------------------------------------------------
    @app.before_request
    def load_user():
        if request.endpoint in ("static", "healthz") or request.blueprint == "api":
            return
        g.db = dbm.connect(app.config["DB_URL"])
        uid = session.get("uid", DEFAULT_USER)
        if not g.db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
            uid = DEFAULT_USER
        g.me = uid
        g.ctl = Controls(g.db, uid)

    @app.teardown_request
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    # ------------------------------------------------------------------
    # Template helpers
    # ------------------------------------------------------------------
    def fmt(ts):
        return datetime.fromtimestamp(ts).strftime("%b %d, %H:%M") if ts else "—"

    def fdate(ts):
        return datetime.fromtimestamp(ts).strftime("%b %d, %Y") if ts else "—"

    def pill(state, label=None):
        return Markup(f'<span class="pill {PILL.get(state, "p-mute")}">{escape(label or state)}</span>')

    def role_names(uid):
        return ", ".join(ROLES[r]["name"] for r in g.ctl.roles_of(uid))

    def btn(key, target="", label=None, variant="", sm=False):
        """A POST button. Locked buttons still submit so the server can log the attempt."""
        target = target or None
        why = g.ctl.reason(key, target)
        text = label or g.ctl.label(key, target)
        cls = "btn" + (" sm" if sm else "") + (" locked" if why else (f" {variant}" if variant else ""))
        title = f' title="{escape(why)}"' if why else ""
        nxt = request.full_path.rstrip("?")
        return Markup(
            f'<form class="inline" method="post" action="{url_for("act", key=key)}">'
            f'<input type="hidden" name="target" value="{escape(target or "")}">'
            f'<input type="hidden" name="next" value="{escape(nxt)}">'
            f'<button class="{cls}" type="submit"{title}>{escape(text)}</button></form>')

    def count(sql):
        return g.db.execute(sql).fetchone()[0]

    def nav():
        c = g.ctl
        return [
            {"label": "Workspace", "links": [{"ep": "dashboard", "label": "Dashboard"}]},
            {"label": "Service operations", "links": [
                {"ep": "incidents", "label": "Incidents", "count": count("SELECT COUNT(*) FROM incidents WHERE state!='Resolved'")},
                {"ep": "changes", "label": "Change requests", "count": count("SELECT COUNT(*) FROM changes WHERE state NOT IN ('Closed','Rejected')")},
                {"ep": "releases", "label": "Releases", "count": count("SELECT COUNT(*) FROM releases WHERE stage<4")},
            ]},
            {"label": "Identity & access", "links": [
                {"ep": "access", "label": "Access requests", "count": count("SELECT COUNT(*) FROM access_requests WHERE state='Pending'")},
                {"ep": "review", "label": "Access review", "locked": not c.can("access.review")},
                {"ep": "roles", "label": "Roles & permissions"},
            ]},
            {"label": "Governance", "links": [
                {"ep": "audit", "label": "Audit log", "locked": not c.can("audit.view")},
                {"ep": "api_tokens", "label": "API tokens"},
            ]},
        ]

    @app.context_processor
    def inject():
        if "ctl" not in g:
            return {}
        users = {r["id"]: dict(r) for r in g.db.execute("SELECT * FROM users ORDER BY id")}
        return dict(
            ctl=g.ctl, me=g.me, me_user=users[g.me], users=users, ROLES=ROLES, PERMS=PERMS, PERM_LABEL=PERM_LABEL,
            pill=pill, btn=btn, fmt=fmt, fdate=fdate, role_names=role_names, nav=nav(),
            freeze=g.ctl.freeze_active(), demo=app.config["DEMO_MODE"],
            now_label=datetime.now().strftime("%b %d, %H:%M"),
        )

    def denied(perm, title):
        holders = [ROLES[r]["name"] for r in ROLES if perm in g.ctl.role_perms(r)]
        return render_template("denied.html", title=title, perm=perm, holders=holders), 403

    def safe_next(default="dashboard"):
        nxt = request.form.get("next", "")
        return nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for(default)

    def say(ok, msg):
        flash(msg, "ok" if ok else "deny")

    # ------------------------------------------------------------------
    # Session / demo
    # ------------------------------------------------------------------
    @app.post("/login")
    def login():
        uid = request.form.get("uid", "")
        if g.db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
            session["uid"] = uid
            flash(f"Signed in as {g.ctl.name(uid)}", "ok")
        return redirect(safe_next())

    @app.post("/reset")
    def reset():
        if not app.config["DEMO_MODE"]:
            abort(404)
        dbm.reset(g.db)
        flash("Demo data reset", "ok")
        return redirect(url_for("dashboard"))

    @app.post("/act/<key>")
    def act(key):
        try:
            ok, msg = g.ctl.perform(key, request.form.get("target") or None)
        except KeyError:
            abort(404)
        say(ok, (msg + " · done") if ok else "Blocked: " + msg)
        return redirect(safe_next())

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------
    @app.get("/")
    def dashboard():
        c, me = g.ctl, g.me
        tasks = []
        for ch in g.db.execute("SELECT * FROM changes WHERE state IN ('Authorize','Assess','Scheduled') ORDER BY id"):
            if ch["state"] == "Authorize" and not c.reason("approve_change", ch["id"]):
                tasks.append(("CAB vote needed", ch["id"], ch["title"], url_for("changes", id=ch["id"])))
            if ch["state"] == "Assess" and not c.reason("send_cab", ch["id"]):
                tasks.append(("Assess change", ch["id"], ch["title"], url_for("changes", id=ch["id"])))
            if ch["state"] == "Scheduled" and ch["implementer"] == me:
                tasks.append(("Implement", ch["id"], ch["title"], url_for("changes", id=ch["id"])))
        for r in g.db.execute("SELECT * FROM releases WHERE stage<4"):
            for gate in ("uat", "rollback"):
                if r["stage"] >= (2 if gate == "uat" else 3) and not c.reason("sign_gate", f"{r['id']}|{gate}"):
                    tasks.append((f"Sign off {GATES[gate].lower()}", r["id"], r["name"], url_for("releases")))
            if r["stage"] == 3 and not c.reason("deploy", r["id"]):
                tasks.append(("Ready to deploy", r["id"], r["name"], url_for("releases")))
        for a in g.db.execute("SELECT * FROM access_requests WHERE state='Pending'"):
            if not c.reason("approve_access", a["id"]):
                tasks.append(("Approve access", a["id"], f"{c.name(a['uid'])} → {ROLES[a['role']]['name']}", url_for("access")))
        for i in g.db.execute("SELECT * FROM incidents WHERE assignee=? AND state!='Resolved'", (me,)):
            tasks.append((f"Resolve P{i['priority']}", i["id"], i["descr"], url_for("incidents")))

        blocked_releases = sum(1 for r in g.db.execute("SELECT * FROM releases WHERE stage<4")
                               if c.missing_gates(r, r["stage"] + 1))
        pending = g.db.execute("SELECT * FROM access_requests WHERE state='Pending'").fetchall()
        stats = {
            "open": count("SELECT COUNT(*) FROM incidents WHERE state!='Resolved'"),
            "p1": count("SELECT COUNT(*) FROM incidents WHERE state!='Resolved' AND priority=1"),
            "cab": count("SELECT COUNT(*) FROM changes WHERE state='Authorize'"),
            "rel": count("SELECT COUNT(*) FROM releases WHERE stage<4"),
            "rel_blocked": blocked_releases,
            "ar": len(pending),
            "ar_conflicts": sum(1 for a in pending if toxic_for(c.roles_of(a["uid"]) + [a["role"]])),
        }
        hour = datetime.now().hour
        greeting = "morning" if hour < 12 else "afternoon" if hour < 18 else "evening"
        my_roles = c.roles_of()
        return render_template(
            "dashboard.html", tasks=tasks, stats=stats, greeting=greeting, my_roles=my_roles,
            my_toxic=toxic_for(my_roles), perm_count=len(c.perms_of()), total_perms=len(PERMS))

    @app.route("/incidents", methods=["GET", "POST"])
    def incidents():
        if request.method == "POST":
            try:
                pri = int(request.form.get("priority", "3"))
            except ValueError:
                pri = 0
            ok, msg = g.ctl.create_incident(request.form.get("descr"), pri)
            say(ok, msg if ok else "Blocked: " + msg)
            return redirect(url_for("incidents"))
        rows = g.db.execute("SELECT * FROM incidents ORDER BY opened DESC").fetchall()
        return render_template("incidents.html", rows=rows, show_form=request.args.get("new") == "1",
                               create_block=g.ctl.need("incident.create"))

    @app.route("/changes", methods=["GET", "POST"])
    def changes():
        c = g.ctl
        if request.method == "POST":
            ok, msg = c.create_change(request.form.get("title"), request.form.get("type"), request.form.get("risk"),
                                      request.form.get("implementer"), request.form.get("win"))
            say(ok, msg if ok else "Blocked: " + msg)
            if ok:
                return redirect(url_for("changes", id=msg.split()[0]))
            return redirect(url_for("changes"))
        rows = g.db.execute(
            "SELECT * FROM changes ORDER BY CASE state WHEN 'Closed' THEN 2 WHEN 'Rejected' THEN 2 ELSE 1 END, id DESC"
        ).fetchall()
        sel_id = request.args.get("id") or (rows[0]["id"] if rows else None)
        sel = next((r for r in rows if r["id"] == sel_id), rows[0] if rows else None)
        detail = None
        if sel:
            votes = c.votes(sel["id"])
            voter_perm = "change.emergency" if sel["type"] == "Emergency" else "change.approve"
            eligible = [u["name"] for u in g.db.execute("SELECT * FROM users ORDER BY id")
                        if c.can(voter_perm, u["id"]) and u["id"] not in (sel["requested_by"], sel["implementer"])]
            flow = CHANGE_FLOW if sel["state"] != "Rejected" else CHANGE_FLOW[:3] + ["Rejected"]
            detail = dict(
                c=sel, votes=votes, eligible=eligible, flow=flow,
                idx=flow.index(sel["state"]) if sel["state"] in flow else 0,
                approvals=sum(1 for v in votes if v["decision"] == "approved"),
                required=REQUIRED_VOTES[sel["type"]])
        users = g.db.execute("SELECT * FROM users ORDER BY name").fetchall()
        return render_template("changes.html", rows=rows, sel=sel, d=detail, people=users,
                               show_form=request.args.get("new") == "1", create_block=c.need("change.create"),
                               types=CHANGE_TYPES, risks=RISKS)

    @app.get("/releases")
    def releases():
        c = g.ctl
        out = []
        for r in g.db.execute("SELECT * FROM releases ORDER BY stage < 4 DESC, id DESC"):
            nxt = r["stage"] + 1
            ch = g.db.execute("SELECT * FROM changes WHERE id=?", (r["change_id"],)).fetchone() if r["change_id"] else None
            gates = []
            for key, label in GATES.items():
                state = c.gate_state(r, key)
                row = c.gate(r["id"], key) if key != "cab" else None
                if key == "cab":
                    who = f"{ch['id']} · {ch['state']}" if ch else "No linked change"
                elif row and row["signed_by"]:
                    who = c.name(row["signed_by"]) if row["signed_by"].startswith("u") else row["signed_by"]
                else:
                    who = "Awaiting sign-off"
                gates.append(dict(key=key, label=label, state=state, who=who, note=row["note"] if row else None,
                                  auto=key in AUTO_GATES,
                                  required_next=nxt <= 4 and key in REQUIRED_GATES[nxt] and state != "pass"))
            out.append(dict(r=r, change=ch, gates=gates, items=(r["items"] or "").split("\n")))
        return render_template("releases.html", releases=out, stages=STAGES)

    @app.route("/access", methods=["GET", "POST"])
    def access():
        c = g.ctl
        if request.method == "POST":
            try:
                days = int(request.form.get("days", "0"))
            except ValueError:
                days = 0
            ok, msg = c.request_access(request.form.get("role"), days, request.form.get("why"))
            say(ok, msg if ok else "Blocked: " + msg)
            return redirect(url_for("access"))
        mine = c.roles_of()
        available = [r for r in ROLES if r not in mine]
        conflicts = {r: toxic_for(mine + [r]) for r in available}
        rows = []
        for a in g.db.execute("SELECT * FROM access_requests ORDER BY requested DESC"):
            rows.append(dict(a=a, conflicts=toxic_for(c.roles_of(a["uid"]) + [a["role"]])))
        return render_template("access.html", available=available, conflicts=conflicts, rows=rows,
                               durations=ACCESS_DURATIONS)

    @app.get("/review")
    def review():
        c = g.ctl
        if not c.can("access.review"):
            return denied("access.review", "Access review")
        now = time.time()
        rows = []
        for a in g.db.execute("SELECT a.*, u.name, u.dept FROM assignments a JOIN users u ON u.id=a.uid ORDER BY u.name, a.id"):
            if a["expires"] and a["expires"] <= now:
                continue
            tox = [t for t in toxic_for(c.roles_of(a["uid"])) if a["role"] in (t[0], t[1])]
            overdue = not a["certified"] or now - a["certified"] > 30 * 86400
            rows.append(dict(a=a, toxic=tox, overdue=overdue))
        done = sum(1 for r in rows if not r["overdue"])
        return render_template("review.html", rows=rows, done=done)

    @app.get("/roles")
    def roles():
        c = g.ctl
        matrix = {r: c.role_perms(r) for r in ROLES}
        members = {r: count(f"SELECT COUNT(*) FROM assignments WHERE role='{r}'") for r in ROLES}
        return render_template("roles.html", matrix=matrix, members=members, editable=c.can("admin.roles"), toxic=TOXIC)

    @app.get("/audit")
    def audit():
        if not g.ctl.can("audit.view"):
            return denied("audit.view", "Audit log")
        rows = g.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()
        blocked = count("SELECT COUNT(*) FROM audit WHERE outcome='denied'")
        total = count("SELECT COUNT(*) FROM audit")
        return render_template("audit.html", rows=rows, blocked=blocked, total=total)

    @app.get("/healthz")
    def healthz():
        with closing(dbm.connect(app.config["DB_URL"])) as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.route("/tokens", methods=["GET", "POST"])
    def api_tokens():
        new_token = None
        if request.method == "POST":
            if request.form.get("revoke"):
                tid = request.form["revoke"]
                row = g.db.execute("SELECT * FROM api_tokens WHERE id=? AND uid=?", (int(tid), g.me)).fetchone()
                if row:
                    tokens.revoke(g.db, int(tid))
                    g.ctl.log(f"Revoked API token “{row['name']}”", None, "allowed")
                    g.db.commit()
                    flash("Token revoked", "ok")
                return redirect(url_for("api_tokens"))
            name = (request.form.get("name") or "").strip()[:60] or "Unnamed token"
            new_token = tokens.create(g.db, g.me, name)
            g.ctl.log(f"Created API token “{name}”", None, "allowed")
            g.db.commit()
        rows = tokens.list_for(g.db, g.me)
        base = request.host_url.rstrip("/")
        return render_template("tokens.html", rows=rows, new_token=new_token, base=base)

    return app


def _register_cli(app):
    import click

    def conn():
        return dbm.connect(app.config["DB_URL"])

    @app.cli.command("init-db")
    def init_db():
        """Create tables (and demo data if the database is empty)."""
        with conn() as c:
            dbm.init(c)
        click.echo(f"Database ready ({'PostgreSQL' if dbm.is_postgres(app.config['DB_URL']) else 'SQLite'}).")

    @app.cli.command("reset-db")
    @click.confirmation_option(prompt="This deletes all data, including the audit log. Continue?")
    def reset_db():
        """Wipe everything and reload the demo data."""
        with conn() as c:
            dbm.reset(c)
        click.echo("Demo data reloaded.")

    @app.cli.command("create-token")
    @click.argument("user_id")
    @click.option("--name", default="CLI token", help="Label shown in the token list.")
    def create_token(user_id, name):
        """Create an API token for USER_ID (e.g. u5). Printed once."""
        with conn() as c:
            try:
                click.echo(tokens.create(c, user_id, name))
            except LookupError as e:
                raise click.ClickException(str(e))

    @app.cli.command("list-tokens")
    def list_tokens():
        """List API tokens (secrets are never stored)."""
        with conn() as c:
            for t in tokens.list_for(c):
                click.echo(f"{t['id']:>4}  {t['uid']:<4} {'revoked' if t['revoked'] else 'active ':<8} {t['name']}")

    @app.cli.command("revoke-token")
    @click.argument("token_id", type=int)
    def revoke_token(token_id):
        """Revoke an API token by id."""
        with conn() as c:
            click.echo("Revoked." if tokens.revoke(c, token_id) else "No such token.")
