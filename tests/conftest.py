"""Run every test against SQLite, and against PostgreSQL when TEST_DATABASE_URL is set.

    TEST_DATABASE_URL=postgresql://user:pass@localhost/meridian_test pytest
"""
import os

import pytest

from meridian import create_app
from meridian import db as dbm

ENGINES = ["sqlite"] + (["postgres"] if os.environ.get("TEST_DATABASE_URL") else [])


@pytest.fixture(params=ENGINES)
def db_url(request, tmp_path):
    if request.param == "sqlite":
        return str(tmp_path / "test.db")
    url = os.environ["TEST_DATABASE_URL"]
    with dbm.connect(url) as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")
    return url


@pytest.fixture
def conn(db_url):
    c = dbm.connect(db_url)
    dbm.init(c)
    yield c
    c.close()


@pytest.fixture
def app(db_url):
    a = create_app(db_url)
    a.config["TESTING"] = True
    return a


@pytest.fixture
def client(app):
    return app, app.test_client()
