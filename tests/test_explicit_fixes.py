"""The structural indicators and the design-rules list are rewritten, not only reported."""

from __future__ import annotations

from pathlib import Path

from vibecleaner.cleanup import fix_tree

_BODY = (
    "def score(qty):\n"
    "    total = qty * 2\n"
    "    total = total + 1\n"
    "    total = total + 1\n"
    "    return total\n"
)


def _write(root: Path, path: str, text: str) -> None:
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def test_a_passthrough_is_removed_and_a_real_wrapper_stays(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "def real(qty):\n"
        "    return qty + 1\n"
        "\n"
        "def wrap(*args, **kwargs):\n"
        "    return real(*args, **kwargs)\n"
        "\n"
        "def run(qty):\n"
        "    value = wrap(qty)\n"
        "    return value\n",
    )
    _write(
        tmp_path,
        "kept.py",
        "def real(qty):\n"
        "    return qty + 1\n"
        "\n"
        "def wrap(*args, **kwargs):\n"
        "    return real(*args, **kwargs) + 1\n",
    )
    fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "def wrap" not in text
    assert "def run" in text
    assert "real(qty)" in text
    assert "def wrap" in (tmp_path / "kept.py").read_text(encoding="utf-8")


def test_a_reexported_wrapper_sends_importers_to_the_real_function(tmp_path: Path) -> None:
    _write(tmp_path, "pkg/real.py", "def amount(qty):\n    return qty + 1\n")
    _write(tmp_path, "pkg/wrap.py", "from pkg.real import amount\n\ndef total(qty):\n    return amount(qty)\n")
    _write(tmp_path, "pkg/use.py", "from pkg.wrap import total\n\ndef run(qty):\n    return total(qty) + 1\n")
    _write(tmp_path, "pkg/more.py", "from pkg.wrap import (\n    total,\n)\n\ndef run(qty):\n    return total(qty) + 2\n")
    fix_tree(tmp_path, use_host=False)
    assert "def total" not in (tmp_path / "pkg/wrap.py").read_text(encoding="utf-8")
    use = (tmp_path / "pkg/use.py").read_text(encoding="utf-8")
    more = (tmp_path / "pkg/more.py").read_text(encoding="utf-8")
    assert "from pkg.real import amount" in use
    assert "amount(qty)" in use
    assert "from pkg.real import amount" in more
    assert "amount(qty)" in more


def test_a_renamed_copy_keeps_the_name_its_callers_use(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", _BODY)
    _write(
        tmp_path,
        "b.py",
        _BODY.replace("def score", "def points", 1) + "\ndef run(qty):\n    value = points(qty)\n    return value\n",
    )
    fix_tree(tmp_path, use_host=False)
    borrowed = (tmp_path / "b.py").read_text(encoding="utf-8")
    assert "from a import score as points" in borrowed
    assert "points(qty)" in borrowed


def test_two_copies_become_one_and_three_copies_share_the_first(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", _BODY + "\ndef run(qty):\n    return score(qty)\n")
    _write(tmp_path, "b.py", _BODY + "\ndef run(qty):\n    return score(qty)\n")
    fix_tree(tmp_path, use_host=False)
    assert "total = qty * 2" in (tmp_path / "a.py").read_text(encoding="utf-8")
    borrowed = (tmp_path / "b.py").read_text(encoding="utf-8")
    assert "from a import score" in borrowed
    assert "total = qty * 2" not in borrowed

    _write(tmp_path, "c.py", _BODY)
    fix_tree(tmp_path, use_host=False)
    third = (tmp_path / "c.py").read_text(encoding="utf-8")
    assert "from a import score" in third
    assert "total = qty * 2" not in third


def test_a_rejected_status_becomes_a_literal_and_a_free_string_stays(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "def parse(kind: str) -> int:\n"
        "    if kind == \"paid\":\n"
        "        return 1\n"
        "    if kind == \"shipped\":\n"
        "        return 2\n"
        "    raise ValueError(kind)\n"
        "\n"
        "def label(kind: str) -> str:\n"
        "    if kind == \"paid\":\n"
        "        return \"paid\"\n"
        "    return kind\n",
    )
    fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "Literal['paid', 'shipped']" in text
    assert "def label(kind: str)" in text


def test_a_route_checks_the_body_and_a_schema_does_not_get_a_second_check(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "@app.post('/charge')\n"
        "def charge(request):\n"
        "    body = request.get_json()\n"
        "    return body['amount']\n",
    )
    _write(
        tmp_path,
        "safe.py",
        "@app.post('/charge')\n"
        "def charge(request):\n"
        "    body = Charge.model_validate(request.get_json())\n"
        "    return body.amount\n",
    )
    fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "missing required field" in text
    assert "missing required field" not in (tmp_path / "safe.py").read_text(encoding="utf-8")


def test_a_script_route_checks_the_body(tmp_path: Path) -> None:
    _write(tmp_path, "api.js", "function charge(req) {\n  return req.body.amount\n}\n")
    _write(tmp_path, "safe.js", "function charge(req) {\n  return chargeSchema.safeParse(req.body)\n}\n")
    fix_tree(tmp_path, use_host=False)
    assert "missing required field" in (tmp_path / "api.js").read_text(encoding="utf-8")
    assert "missing required field" not in (tmp_path / "safe.js").read_text(encoding="utf-8")


def test_copies_with_different_argument_names_share_one_body(tmp_path: Path) -> None:
    first = (
        "def score(qty):\n"
        "    total = qty * 2\n"
        "    total = total + 1\n"
        "    total = total + 1\n"
        "    return total\n"
    )
    second = first.replace("def score(qty)", "def points(count)").replace("qty", "count")
    _write(tmp_path, "a.py", first)
    _write(tmp_path, "b.py", second + "\ndef run(count):\n    value = points(count)\n    return value\n")
    fix_tree(tmp_path, use_host=False)
    borrowed = (tmp_path / "b.py").read_text(encoding="utf-8")
    assert "from a import score as points" in borrowed
    assert "total = count * 2" not in borrowed


def test_every_importer_in_one_feature_pulls_the_layer_file(tmp_path: Path) -> None:
    _write(tmp_path, "utils/price.py", "def amount(qty):\n    return qty * 2\n")
    _write(tmp_path, "orders/charge.py", "from utils.price import amount\n")
    _write(tmp_path, "orders/refund.py", "from utils.price import amount\n")
    _write(tmp_path, "shipping/label.py", "from utils.tax import rate\n")
    _write(tmp_path, "utils/tax.py", "def rate(qty):\n    return qty\n")
    _write(tmp_path, "warehouse/invoice.py", "from utils.tax import rate\n")
    fix_tree(tmp_path, use_host=False)
    assert not (tmp_path / "utils/price.py").exists()
    assert (tmp_path / "orders/price.py").is_file()
    assert (tmp_path / "utils/tax.py").is_file()


def test_a_lookup_through_get_uses_the_same_constant(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "def save(row):\n    row['order_status'] = 'paid'\n    return row\n")
    _write(tmp_path, "b.py", "def read(row):\n    return row.get('order_status')\n")
    fix_tree(tmp_path, use_host=False)
    assert "row.get(ORDER_STATUS)" in (tmp_path / "b.py").read_text(encoding="utf-8")


def test_a_status_compared_on_either_side_becomes_a_literal(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        "def parse(kind):\n"
        "    if \"paid\" == kind:\n"
        "        return 1\n"
        "    if \"shipped\" == kind:\n"
        "        return 2\n"
        "    raise ValueError(f'bad {kind}')\n",
    )
    fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "Literal['paid', 'shipped']" in text


def test_a_title_case_heading_becomes_sentence_case(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "page.html",
        "<html><head><title>Shop</title></head><body><h1>Get Started</h1><button>Save</button></body></html>\n",
    )
    fix_tree(tmp_path, use_host=False)
    page = (tmp_path / "page.html").read_text(encoding="utf-8")
    assert "Get started" in page
    assert "<button>Save</button>" in page


def test_a_shared_key_becomes_a_constant(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "def save(row):\n    row['order_status'] = 'paid'\n    return row\n")
    _write(tmp_path, "b.py", "def read(row):\n    return row['order_status']\n")
    _write(tmp_path, "c.py", "def read(row):\n    return row['name']\n")
    fix_tree(tmp_path, use_host=False)
    home = (tmp_path / "a.py").read_text(encoding="utf-8")
    other = (tmp_path / "b.py").read_text(encoding="utf-8")
    assert 'ORDER_STATUS = "order_status"' in home
    assert "row[ORDER_STATUS]" in home
    assert "from a import ORDER_STATUS" in other
    assert "row['name']" in (tmp_path / "c.py").read_text(encoding="utf-8")


def test_an_inner_layer_stops_importing_the_outer_one(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "models/order.py",
        "from services.pricing import price\n\ndef total(qty):\n    billed = price(qty)\n    return billed\n",
    )
    _write(tmp_path, "services/pricing.py", "def price(qty):\n    return qty * 2\n")
    _write(
        tmp_path,
        "services/tax.py",
        "from models.order import total\n\ndef due(qty):\n    amount = total(qty)\n    return amount\n",
    )
    fix_tree(tmp_path, use_host=False)
    order = (tmp_path / "models/order.py").read_text(encoding="utf-8")
    assert "from services.pricing import price" not in order
    assert "def price(qty):" in order
    assert "def due" in (tmp_path / "services/tax.py").read_text(encoding="utf-8")


def test_a_god_file_moves_its_queries_out(tmp_path: Path) -> None:
    queries = "".join(f"def query_{i}(db):\n    return db.execute('SELECT {i}')\n" for i in range(8))
    pads = "".join(f"def pad_{i}(n):\n    return n\n" for i in range(260))
    route = "@app.get('/health')\ndef health():\n    return {'ok': True}\n"
    _write(tmp_path, "app.py", queries + route + pads)
    _write(tmp_path, "small.py", "def query(db):\n    return db.execute('SELECT 1')\n\n@app.get('/health')\ndef health():\n    return {'ok': True}\n")
    fix_tree(tmp_path, use_host=False)
    app = (tmp_path / "app.py").read_text(encoding="utf-8")
    db = (tmp_path / "app_db.py").read_text(encoding="utf-8")
    assert "from app_db import" in app
    assert "def health" in app
    assert "def query_0" in db
    assert "def query_0" not in app
    assert not (tmp_path / "small_db.py").exists()


def test_a_single_importer_pulls_a_layer_file_into_the_feature(tmp_path: Path) -> None:
    _write(tmp_path, "utils/price.py", "def amount(qty):\n    return qty * 2\n")
    _write(tmp_path, "orders/charge.py", "from utils.price import amount\n\ndef total(qty):\n    return amount(qty)\n")
    _write(tmp_path, "shared.py", "def amount(qty):\n    return qty\n")
    _write(tmp_path, "one.py", "from shared import amount\n")
    _write(tmp_path, "two.py", "from shared import amount\n")
    fix_tree(tmp_path, use_host=False)
    assert not (tmp_path / "utils/price.py").exists()
    assert "def amount" in (tmp_path / "orders/price.py").read_text(encoding="utf-8")
    assert "from orders.price import amount" in (tmp_path / "orders/charge.py").read_text(encoding="utf-8")
    assert (tmp_path / "shared.py").is_file()


def test_design_rules_rewrite_the_ai_surface_and_leave_a_calm_page(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "page.html",
        "<html><head><title>Shop</title></head><body>\n"
        "<p class=\"eyebrow\">FEATURES</p>\n"
        "<h1>GET STARTED</h1>\n"
        "<span class=\"pill\">New</span>\n"
        "<div class=\"card\"><div class=\"card\">Inner</div></div>\n"
        "<div class=\"icon rounded-full\">★</div>\n"
        "<button class=\"font-bold uppercase shadow-lg bg-gradient-to-r from-purple-500\">Save</button>\n"
        "<p style=\"color: #7C3AED; font-weight: 700; transition: 600ms ease-in-out;\">Hello</p>\n"
        "</body></html>\n",
    )
    _write(
        tmp_path,
        "calm.html",
        "<html><head><title>Shop</title></head><body>\n"
        "<h1>Get started</h1>\n"
        "<button>Save</button>\n"
        "</body></html>\n",
    )
    fix_tree(tmp_path, use_host=False)
    page = (tmp_path / "page.html").read_text(encoding="utf-8")
    assert "eyebrow" not in page
    assert "GET STARTED" not in page
    assert "Get started" in page
    assert "pill" not in page
    assert page.count("card") == 1
    assert "rounded-full" not in page
    assert "font-bold" not in page
    assert "uppercase" not in page
    assert "bg-gradient" not in page
    assert "#7C3AED" not in page
    assert "var(--accent)" in page
    assert "600ms" not in page
    assert "font-weight: 500" in page or "font-weight:500" in page
    assert "max-width: 390px" in page
    assert "prefers-color-scheme: dark" in page
    assert ":focus-visible" in page
    calm = (tmp_path / "calm.html").read_text(encoding="utf-8")
    assert "Get started" in calm
    assert "<button>Save</button>" in calm
    assert fix_tree(tmp_path, use_host=False).changed == ()
