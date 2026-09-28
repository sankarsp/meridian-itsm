# Meridian ITSM

A ServiceNow-style IT service management app in Python (Flask), backed by PostgreSQL or SQLite. It has:

- **Roles and access:** 7 roles and 16 permissions, an editable role matrix, time-bound access requests, and quarterly access certification.
- **Controls:** segregation of duties, a change freeze, and release gates, all enforced on the server.
- **Change management:** Standard, Normal and Emergency changes with a CAB/ECAB workflow.
- **Release management:** a Dev → QA → UAT → Staging → Production pipeline.
- **REST API:** everything the screens can do, with bearer tokens and a CI/CD webhook.
- **Audit:** an append-only audit log that the database itself protects.

## Run it

**Quickest (SQLite, no setup):**
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python wsgi.py                                          # http://localhost:5000
```

**With PostgreSQL (Docker):**
```bash
docker compose up --build                               # http://localhost:8000
```

**With your own PostgreSQL:**
```bash
export DATABASE_URL=postgresql://user:password@host:5432/meridian
flask --app wsgi init-db
python wsgi.py
```

Use **Signed in as** at the top of the page to switch between the demo users. **Reset demo data**, in the sidebar, restores the starting state.

## Database

The app picks the engine from `DATABASE_URL`: a `postgresql://` URL uses PostgreSQL, and anything else is treated as a SQLite file path. The schema is created on first start. Demo data is loaded only into an empty database.

```mermaid
erDiagram
  users ||--o{ assignments : "holds roles"
  users ||--o{ api_tokens : owns
  role_perms }o--|| assignments : "role grants perms"
  users ||--o{ incidents : "calls / is assigned"
  users ||--o{ changes : "requests / implements"
  changes ||--o{ votes : "CAB votes"
  users ||--o{ votes : casts
  changes ||--o| releases : authorizes
  releases ||--|{ gates : "quality gates"
  users ||--o{ access_requests : requests
  users ||--o{ audit : "every action"
```

| Table | What it holds |
|---|---|
| `users` | People |
| `assignments` | Who holds which role, with optional expiry and last-certified date |
| `role_perms` | The role → permission matrix, editable by IAM Administrators |
| `incidents`, `changes`, `votes` | Service operations and CAB decisions |
| `releases`, `gates` | Pipeline stage and gate status (build, sec, uat, rollback; `cab` comes from the linked change) |
| `access_requests` | Role requests, decisions and SoD exceptions |
| `api_tokens` | API tokens, stored as SHA-256 hashes only |
| `audit` | Every allowed and blocked action, with the user's roles at the time and whether it came from the web or the API |
| `settings` | The change freeze flag |

**The audit log is append-only at the database level.** Triggers reject `UPDATE`, `DELETE` and, on Postgres, `TRUNCATE`. The only exception is the demo reset. In production, also give the app's database user only `INSERT` and `SELECT` on `audit`.

**CLI:**
```bash
flask --app wsgi init-db                 # create tables (+ demo data if empty)
flask --app wsgi reset-db                # wipe and reload demo data
flask --app wsgi create-token u5 --name "GitHub Actions"
flask --app wsgi list-tokens
flask --app wsgi revoke-token 3
```

## REST API

The API lives at `/api/v1` and is fully described in [`docs/openapi.yaml`](docs/openapi.yaml). You can load that file into Swagger UI or Postman.

A token acts as its user, with exactly that user's roles. Every call passes through the same checks as the screens: permissions, segregation of duties, the freeze and the gates. Each write is audited with `channel = "api"`. To create a token, use the **API tokens** page in the app or the CLI.

| Method | Path | What it does |
|---|---|---|
| GET | `/me` | Your user, roles, permissions, SoD exceptions |
| GET | `/users`, `/roles` | Users with active roles; the role matrix |
| GET, POST | `/incidents` | List (`?state=`), or log an incident |
| GET | `/incidents/{id}` | One incident |
| GET, POST | `/changes` | List with votes (`?state=`), or raise a change |
| GET | `/changes/{id}` | One change with its votes |
| GET | `/releases`, `/releases/{id}` | Releases with gate status and what's missing for the next stage |
| POST | `/releases/{id}/gates/{build\|sec}` | **CI/CD webhook:** report a pipeline result |
| GET, POST | `/access-requests` | List with SoD conflicts, or request a role |
| GET | `/assignments` | All role assignments (needs `access.review`) |
| GET | `/audit` | Audit log (`?limit=&outcome=denied`; needs `audit.view`) |
| GET | `/actions?target=ID` | Which actions you can run on a record, and why not |
| POST | `/actions/{key}` | Run a workflow action: `{"target": "CHG0030412"}` |

The API returns these error codes: `400 invalid`, `401 unauthorized`, `403 forbidden` (missing permission), `404 not_found`, and `409 blocked_by_control` (SoD, freeze, gate or workflow state). Every error body includes a `message` saying exactly why.

**Example: the release walkthrough over the API**
```bash
BASE=http://localhost:5000/api/v1
SOFIA=$(flask --app wsgi create-token u6)     # CAB member
DAVID=$(flask --app wsgi create-token u5)     # Release manager
RAJ=$(flask --app wsgi create-token u3)       # Developer who built the release

# Raj can't deploy: 403 forbidden
curl -s -X POST $BASE/actions/deploy -H "Authorization: Bearer $RAJ" \
     -H "Content-Type: application/json" -d '{"target":"REL-26.10"}'

# Sofia casts the second CAB vote, David signs the rollback gate and deploys
curl -s -X POST $BASE/actions/approve_change -H "Authorization: Bearer $SOFIA" \
     -H "Content-Type: application/json" -d '{"target":"CHG0030412"}'
curl -s -X POST $BASE/actions/sign_gate -H "Authorization: Bearer $DAVID" \
     -H "Content-Type: application/json" -d '{"target":"REL-26.10|rollback"}'
curl -s -X POST $BASE/actions/deploy -H "Authorization: Bearer $DAVID" \
     -H "Content-Type: application/json" -d '{"target":"REL-26.10"}'
```

**Example: report a security scan from GitHub Actions**
```yaml
- name: Report scan to Meridian
  run: |
    curl -sf -X POST "$MERIDIAN_URL/api/v1/releases/REL-26.11/gates/sec" \
      -H "Authorization: Bearer ${{ secrets.MERIDIAN_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d '{"status":"pass","note":"0 high, 2 medium findings"}'
```

## Tests

```bash
pytest -q                                                          # SQLite
TEST_DATABASE_URL=postgresql://user:pass@localhost/meridian_test pytest -q   # + PostgreSQL
```

The suite has 86 tests, and each one runs on both engines. They try to break the controls through both the web and the API:

- Forged requests.
- Double votes.
- Deploying your own release, even after gaining the Release Manager role.
- Deploying during a freeze.
- Self-approval of access.
- Revoked tokens.
- Editing the audit log.

**Warning:** the Postgres test run drops and recreates the `public` schema of `TEST_DATABASE_URL`. Point it at a throwaway database.

## Deploy

GitHub Pages can't host this app, because it needs a Python server. Instead, push the code to GitHub and connect one of these hosts:

- **Render:** create a Web Service from the repo and add a Render PostgreSQL database.
  - Build command: `pip install -r requirements.txt`
  - Start command: `gunicorn -w 2 -b 0.0.0.0:$PORT wsgi:app`
  - Environment: set `DATABASE_URL` to the database's internal URL, and `SECRET_KEY` to a long random string.
- **Azure App Service or AWS (ECS or App Runner):** use the Dockerfile with Azure Database for PostgreSQL or Amazon RDS.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL URL. When set, it takes priority over `MERIDIAN_DB`. |
| `MERIDIAN_DB` | `instance/meridian.db` | SQLite file path, used when `DATABASE_URL` isn't set |
| `SECRET_KEY` | `dev-only-change-me` | Signs session cookies. **Always set in production.** |
| `MERIDIAN_DEMO` | `1` | Set `0` to remove the Reset button |

## Before real use

1. **Replace the demo sign-in with SSO.** Use OIDC or SAML through Okta or Entra ID, and map directory groups to roles. Remove `/login` and `/reset`.
2. **Add CSRF tokens to the web forms**, for example with Flask-WTF. The API uses bearer tokens, so it isn't exposed to CSRF.
3. **Harden the database.** Use a connection pool (`psycopg_pool`), schema migrations (Alembic), backups, and the `INSERT`/`SELECT`-only grant on `audit`.
4. **Add rate limiting** on `/api` (for example Flask-Limiter), and set token expiry dates.
5. **Ship the audit log to write-once storage or a SIEM** for regulatory retention.

## Project layout

```
meridian/
  __init__.py     Web app: routes, pages, CLI commands
  api.py          REST API (/api/v1)
  rbac.py         Roles, permissions, SoD rules, every action and its checks
  db.py           PostgreSQL/SQLite layer, schema, append-only triggers, demo data
  tokens.py       API token creation, hashing, revocation
  templates/      Web pages
  static/         Stylesheet
docs/openapi.yaml API specification
tests/            Controls and API tests (run on both databases)
docker-compose.yml  App + PostgreSQL
```

To add a new workflow action, register it in `rbac.py` with `@action(...)`. Give it a permission, a check that returns the block reason (or `None` when the action is allowed), and a run function. The web buttons, the API, enforcement and the audit log all pick it up automatically.
