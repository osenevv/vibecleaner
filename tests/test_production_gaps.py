"""Each production gap has a hit and a lookalike that stays quiet."""

from __future__ import annotations

from pathlib import Path

from vibecleaner.collector import collect
from vibecleaner.models import Finding, SourceFile
from vibecleaner.production import advisories_in, production_findings, suppress


def _file(path: str, text: str) -> SourceFile:
    return SourceFile(path, Path(path), _language(path), text)


def _language(path: str):
    from vibecleaner.models import Language

    if path.endswith(".py"):
        return Language.PYTHON
    if path.endswith(".ts") or path.endswith(".tsx"):
        return Language.TYPESCRIPT
    return Language.OTHER


def _ids(findings: list[Finding]) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_weak_crypto_flags_md5_and_a_secret_drawn_from_random() -> None:
    bad = _file("auth.py", "import hashlib, random\ndef token():\n    return hashlib.md5(random.choice(['a']).encode()).hexdigest()\n")
    good = _file("cache.py", "import hashlib, random\ndef etag(body):\n    return hashlib.sha256(body).hexdigest()\ndef roll():\n    return random.random()\n")
    assert "D1.weak_crypto" in _ids(production_findings(Path("."), [bad]))
    assert "D1.weak_crypto" not in _ids(production_findings(Path("."), [good]))


def test_unsafe_sinks_flag_pickle_yaml_html_shell_and_sql() -> None:
    bad = _file(
        "load.py",
        "import pickle, yaml, os\n"
        "def run(blob, raw, cmd):\n"
        "    pickle.loads(blob)\n"
        "    yaml.load(raw)\n"
        "    os.system(cmd)\n"
        "    db.execute(f'SELECT {raw}')\n",
    )
    page = _file("view.tsx", "export const View = (html) => <div dangerouslySetInnerHTML={{__html: html}} />\n")
    good = _file(
        "safe.py",
        "import yaml\n"
        "def run(raw):\n"
        "    return yaml.safe_load(raw)\n",
    )
    assert "D5.unsafe_sink" in _ids(production_findings(Path("."), [bad, page]))
    assert "D5.unsafe_sink" not in _ids(production_findings(Path("."), [good]))


def test_open_without_with_and_a_timer_without_a_clear_are_leaks() -> None:
    bad = _file("io.py", "def read(path):\n    handle = open(path)\n    return handle.read()\n")
    timer = _file("clock.js", "const id = setInterval(tick, 1000)\n")
    socket = _file("net.py", "import socket\ndef connect():\n    sock = socket.socket()\n    return sock\n")
    listener = _file("ui.js", "button.addEventListener('click', onClick)\n")
    good = _file("io.py", "def read(path):\n    with open(path) as handle:\n        return handle.read()\n")
    cleared = _file("clock.js", "const id = setInterval(tick, 1000)\nclearInterval(id)\n")
    assert "D8.resource_leak" in _ids(production_findings(Path("."), [bad, timer, socket, listener]))
    assert "D8.resource_leak" not in _ids(production_findings(Path("."), [good, cleared]))


def test_async_check_then_act_without_a_lock_is_a_race() -> None:
    bad = _file(
        "cache.py",
        "async def fill(cache, key, value):\n"
        "    if key not in cache:\n"
        "        cache[key] = value\n",
    )
    good = _file(
        "cache.py",
        "async def fill(cache, key, value, lock):\n"
        "    async with lock:\n"
        "        if key not in cache:\n"
        "            cache[key] = value\n",
    )
    assert "D8.shared_state_race" in _ids(production_findings(Path("."), [bad]))
    assert "D8.shared_state_race" not in _ids(production_findings(Path("."), [good]))
    threaded = _file(
        "jobs.py",
        "import threading\n"
        "def fill(cache, key, value):\n"
        "    if key not in cache:\n"
        "        cache[key] = value\n"
        "def start(cache, key, value):\n"
        "    threading.Thread(target=fill).start()\n",
    )
    guarded = _file(
        "jobs.py",
        "import threading\n"
        "def fill(cache, key, value, lock):\n"
        "    with lock:\n"
        "        if key not in cache:\n"
        "            cache[key] = value\n"
        "def start(cache, key, value, lock):\n"
        "    threading.Thread(target=fill).start()\n",
    )
    assert "D8.shared_state_race" in _ids(production_findings(Path("."), [threaded]))
    assert "D8.shared_state_race" not in _ids(production_findings(Path("."), [guarded]))


def test_a_request_without_a_timeout_is_flagged() -> None:
    bad = _file("net.py", "import requests\ndef load(url):\n    return requests.get(url)\n")
    good = _file("net.py", "import requests\ndef load(url):\n    return requests.get(url, timeout=5)\n")
    assert "D8.missing_timeout" in _ids(production_findings(Path("."), [bad]))
    assert "D8.missing_timeout" not in _ids(production_findings(Path("."), [good]))
    session = _file("net.py", "import aiohttp\nasync def load(session, url):\n    return await session.get(url)\n")
    limited = _file("net.py", "import aiohttp\nasync def load(session, url):\n    return await session.get(url, timeout=5)\n")
    assert "D8.missing_timeout" in _ids(production_findings(Path("."), [session]))
    assert "D8.missing_timeout" not in _ids(production_findings(Path("."), [limited]))


def test_openapi_paths_must_match_the_routes(tmp_path: Path) -> None:
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\npaths:\n  /health:\n    get:\n      responses: {}\n", encoding="utf-8")
    app = _file("app.py", "@app.get('/charge')\ndef charge():\n    return {'ok': True}\n")
    assert "D9.contract_drift" in _ids(production_findings(tmp_path, [app]))
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\npaths:\n  /charge:\n    get:\n      responses: {}\n", encoding="utf-8")
    assert "D9.contract_drift" not in _ids(production_findings(tmp_path, [app]))
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\npaths:\n  /charge:\n    post:\n      responses: {}\n", encoding="utf-8")
    assert "D9.contract_drift" in _ids(production_findings(tmp_path, [app]))


def test_a_drop_and_a_blocking_index_are_migration_hazards() -> None:
    bad = _file("migrations/001.sql", "DROP COLUMN email;\nCREATE INDEX users_email ON users(email);\n")
    good = _file("migrations/002.sql", "ADD COLUMN email TEXT;\nCREATE INDEX CONCURRENTLY users_email ON users(email);\n")
    assert "D9.migration_hazard" in _ids(production_findings(Path("."), [bad]))
    assert "D9.migration_hazard" not in _ids(production_findings(Path("."), [good]))


def test_a_read_env_key_must_be_in_the_example(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("PORT=\n", encoding="utf-8")
    bad = _file("app.py", "import os\nname = os.environ['APP_NAME']\n")
    good = _file("app.py", "import os\nport = os.environ['PORT']\n")
    assert "D9.env_parity" in _ids(production_findings(tmp_path, [bad]))
    assert "D9.env_parity" not in _ids(production_findings(tmp_path, [good]))


def test_a_test_without_an_assertion_and_a_network_call_are_flagged() -> None:
    bad = _file("tests/test_gap.py", "def test_empty():\n    value = 1\n")
    taut = _file("tests/test_true.py", "def test_true():\n    assert True\n")
    flaky = _file("tests/test_clock.py", "import time\ndef test_now():\n    assert time.time() > 0\n")
    good = _file("tests/test_ok.py", "def test_add():\n    assert 1 + 1 == 2\n")
    assert "D9.assertion_gap" in _ids(production_findings(Path("."), [bad, taut]))
    assert "D9.flaky_test" in _ids(production_findings(Path("."), [flaky]))
    assert _ids(production_findings(Path("."), [good])) == set()


def test_a_pasted_prompt_is_flagged_and_can_be_ignored() -> None:
    bad = _file("notes.py", "# You are a helpful assistant. Write the function.\ndef run():\n    return 1\n")
    ignored = _file("notes.py", "# unslop-ignore: D9.prompt_leak\n# You are a helpful assistant.\ndef run():\n    return 1\n")
    hit = production_findings(Path("."), [bad])
    assert "D9.prompt_leak" in _ids(hit)
    assert suppress([ignored], production_findings(Path("."), [ignored])) == []


def test_a_route_that_writes_without_a_log_is_flagged() -> None:
    bad = _file(
        "app.py",
        "@app.post('/charge')\ndef charge(db):\n    db.execute('insert')\n    return {'ok': True}\n",
    )
    good = _file(
        "app.py",
        "@app.post('/charge')\ndef charge(db, logger):\n    db.execute('insert')\n    logger.info('charged')\n    return {'ok': True}\n",
    )
    assert "D9.missing_telemetry" in _ids(production_findings(Path("."), [bad]))
    assert "D9.missing_telemetry" not in _ids(production_findings(Path("."), [good]))


def test_loop_io_boundary_and_graphql(tmp_path: Path) -> None:
    loop = _file(
        "db.py",
        "def load(rows, db):\n"
        "    found = []\n"
        "    for row in rows:\n"
        "        found.append(db.execute(row))\n"
        "    return found\n",
    )
    batched = _file(
        "db.py",
        "def load(rows, db):\n"
        "    return db.execute(rows)\n",
    )
    raw = _file(
        "app.py",
        "@app.post('/charge')\n"
        "def charge(request):\n"
        "    body = request.get_json()\n"
        "    return body['amount']\n",
    )
    checked = _file(
        "app.py",
        "@app.post('/charge')\n"
        "def charge(request):\n"
        "    body = Charge.model_validate(request.get_json())\n"
        "    return body.amount\n",
    )
    assert "D9.loop_io" in _ids(production_findings(tmp_path, [loop]))
    assert "D9.loop_io" not in _ids(production_findings(tmp_path, [batched]))
    lookup = _file(
        "app.py",
        "def names(rows):\n"
        "    found = []\n"
        "    for row in rows:\n"
        "        found.append(row.get('name'))\n"
        "    return found\n",
    )
    assert "D9.loop_io" not in _ids(production_findings(tmp_path, [lookup]))
    assert "D9.boundary_schema" in _ids(production_findings(tmp_path, [raw]))
    assert "D9.boundary_schema" not in _ids(production_findings(tmp_path, [checked]))
    raw_js = _file("api.ts", "export function charge(req) {\n  return req.body.amount\n}\n")
    parsed_js = _file("api.ts", "export function charge(req) {\n  return chargeSchema.safeParse(req.body)\n}\n")
    assert "D9.boundary_schema" in _ids(production_findings(tmp_path, [raw_js]))
    assert "D9.boundary_schema" not in _ids(production_findings(tmp_path, [parsed_js]))
    (tmp_path / "schema.graphql").write_text("type Query {\n  charge(id: ID!): String\n  ping: String\n}\n", encoding="utf-8")
    resolver = _file("api.py", "def resolve_ping():\n    return 'ok'\n")
    drift = _ids(production_findings(tmp_path, [resolver]))
    assert "D9.graphql_drift" in drift
    both = _file("api.py", "def resolve_ping():\n    return 'ok'\n\ndef resolve_charge(id):\n    return id\n")
    assert "D9.graphql_drift" not in _ids(production_findings(tmp_path, [both]))


def test_an_osv_body_names_the_advisory_and_an_empty_body_does_not() -> None:
    assert advisories_in({"vulns": [{"id": "GHSA-1111"}]}) == ["GHSA-1111"]
    assert advisories_in({"vulns": []}) == []
    assert advisories_in(None) == []


def test_a_silent_pass_is_reported_and_left_in_place(tmp_path: Path) -> None:
    from vibecleaner.cleanup import fix_tree
    from vibecleaner.deterministic import detect_silent_exceptions
    from vibecleaner.models import Language

    source = "def run(value):\n    try:\n        return value\n    except Exception:\n        pass\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    fix_tree(tmp_path, use_host=False)
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == source
    unit = SourceFile("app.py", Path("app.py"), Language.PYTHON, source)
    assert any(item.rule_id == "D6a.silent_exception" for item in detect_silent_exceptions(unit))


def test_a_one_edit_dependency_name_is_a_slopsquat(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\ndependencies = ["reqeusts>=2"]\n',
        encoding="utf-8",
    )
    assert "D9.slopsquat" in _ids(production_findings(tmp_path, []))
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\ndependencies = ["requests>=2"]\n',
        encoding="utf-8",
    )
    assert "D9.slopsquat" not in _ids(production_findings(tmp_path, []))


def test_eval_and_inner_html_are_sinks_and_a_literal_parse_is_not() -> None:
    bad = _file("app.py", "def run(text):\n    return eval(text)\n")
    good = _file("app.py", "import ast\ndef run(text):\n    return ast.literal_eval(text)\n")
    html = _file("ui.tsx", "node.innerHTML = body\n")
    assert "D5.unsafe_sink" in _ids(production_findings(Path("."), [bad, html]))
    assert "D5.unsafe_sink" not in _ids(production_findings(Path("."), [good]))


def test_an_exact_pin_is_read_and_a_range_is_not(tmp_path: Path) -> None:
    from vibecleaner.production import _pinned_python

    (tmp_path / "requirements.txt").write_text("requests==2.32.0\nflask>=3\n", encoding="utf-8")
    assert _pinned_python(tmp_path) == [("requests", "2.32.0")]


def test_an_edit_that_drops_a_log_is_held() -> None:
    from vibecleaner.cleanup import _lost_signal

    before = "def charge():\n    logger.info('charged')\n    return 1\n"
    after = "def charge():\n    return 1\n"
    assert _lost_signal(before, after)
    assert not _lost_signal(before, before)


def test_preflight_names_a_drop_and_leaves_an_add_unchecked(tmp_path: Path) -> None:
    from vibecleaner.models import Language, ScanContext
    from vibecleaner.preflight.results import Status
    from vibecleaner.preflight.section_d import check_29
    from vibecleaner.preflight.view import RepoView

    drop = SourceFile(
        "migrations/001.sql",
        tmp_path / "001.sql",
        Language.SQL,
        "ALTER TABLE users DROP COLUMN email;\n",
    )
    warning = check_29(RepoView(ScanContext(tmp_path, [drop], [], ""), []))
    assert warning.status == Status.WARNING
    assert warning.locations == ["migrations/001.sql:1"]
    added = SourceFile(
        "migrations/002.sql",
        tmp_path / "002.sql",
        Language.SQL,
        "ALTER TABLE users ADD COLUMN email TEXT;\n",
    )
    quiet = check_29(RepoView(ScanContext(tmp_path, [added], [], ""), []))
    assert quiet.status == Status.NOT_CHECKED
