"""Proven slop edits delete residue, keep lookalikes, and do nothing the second time."""

from __future__ import annotations

import json
from pathlib import Path

from vibecleaner.cleanup import fix_tree, revert_rule
from vibecleaner.cli import main

_APP = '''\
PRICE = "12"

def quote(qty):
    """The button says Save."""
    return {"ok": True, "price": 0}

def real_total(qty):
    return qty * 12

def ready():
    return "ok"

def unsupported(system, prompt):
    return None

def guarded(value):
    try:
        return value
    except Exception:
        raise

def logged(value):
    try:
        return value
    except Exception as exc:
        print(exc)
        raise

def _old_quote(qty):
    return qty

# TODO: implement the real total later
breakpoint()
'''

_PAGE = """\
<!DOCTYPE html>
<html>
<head>
<title>Acme</title>
</head>
<body style="background: linear-gradient(blue, purple); backdrop-filter: blur(8px);">
<h1>Acme</h1>
<p>Acme charges $12 for the job.</p>
<p>This seamless platform unlocks a cutting-edge future for every team.</p>
<p>In a world of endless possibility this paragraph explains nothing about the product and could sit on any other page unchanged today.</p>
<button class="equal">One</button>
<button class="equal">Two</button>
<button class="equal">Three</button>
<button class="equal">Four</button>
<button class="equal">Five</button>
<button class="equal">Six</button>
</body>
</html>
"""

_DOC = """\
# Acme

The price is $12.

This seamless platform unlocks a cutting-edge future.

```
This seamless quotation stays.
```

Run the scan before you ship.
"""


def test_code_edits_remove_residue_and_keep_lookalikes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_APP, encoding="utf-8")
    report = fix_tree(tmp_path, use_host=False)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "breakpoint" not in text
    assert "TODO: implement" not in text
    assert '{"ok": True, "price": 0}' not in text
    assert "return real_total(qty)" in text
    assert "def quote(qty):" in text
    assert "return qty * 12" in text
    assert 'return "ok"' in text
    assert "return None" in text
    assert "print(exc)" in text
    assert "def guarded" in text
    assert "except Exception:\n        raise" not in text
    assert report.changed == ("app.py",)
    second = fix_tree(tmp_path, use_host=False)
    assert second.changed == ()
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == text


def test_words_and_surface_keep_facts(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(_PAGE, encoding="utf-8")
    (tmp_path / "README.md").write_text(_DOC, encoding="utf-8")
    report = fix_tree(tmp_path, use_host=False)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    doc = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "Acme charges $12" in page
    assert "seamless" not in page
    assert "endless possibility" not in page
    assert "linear-gradient" not in page
    assert "viewport" in page
    assert "The price is $12." in doc
    assert "seamless platform" not in doc
    assert "This seamless quotation stays." in doc
    assert page.count("<button") == 1
    assert "equal_buttons" not in " ".join(report.remaining)
    second = fix_tree(tmp_path, use_host=False)
    assert second.changed == ()


def test_cli_fix_is_idempotent(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("def quote(qty):\n    return {'ok': True}\n", encoding="utf-8")
    assert main(["fix", str(tmp_path), "--no-host", "--json"]) == 0
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "stub: quote" in text
    capsys.readouterr()
    assert main(["fix", str(tmp_path), "--no-host", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["changed"] == []
    assert payload["workers"] == 1


def test_company_languages_lose_the_same_residue(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "import \"fmt\"\n"
        "\n"
        "// qty is cents, not dollars\n"
        "// TODO: implement the handler later\n"
        "func Total(qty int) int {\n"
        "\tfmt.Println(qty)\n"
        "\treturn qty\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "Bill.java").write_text(
        "class Bill {\n"
        "    // temporary hack before launch\n"
        "    int charge(int qty) { return qty * 12; }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "lib.rs").write_text(
        "// in a real system we would check the token\n"
        "fn total(qty: i32) -> i32 { qty }\n",
        encoding="utf-8",
    )
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.go").write_text("// TODO: implement the handler later\n", encoding="utf-8")
    report = fix_tree(tmp_path, use_host=False)
    go = (tmp_path / "main.go").read_text(encoding="utf-8")
    assert "TODO: implement" not in go
    assert "qty is cents, not dollars" in go
    assert "fmt.Println(qty)" in go
    assert "temporary hack" not in (tmp_path / "Bill.java").read_text(encoding="utf-8")
    assert "charge(int qty)" in (tmp_path / "Bill.java").read_text(encoding="utf-8")
    assert "in a real system" not in (tmp_path / "lib.rs").read_text(encoding="utf-8")
    assert "fn total" in (tmp_path / "lib.rs").read_text(encoding="utf-8")
    assert (vendor / "lib.go").read_text(encoding="utf-8").startswith("// TODO")
    assert "vendor/lib.go" not in report.changed
    assert fix_tree(tmp_path, use_host=False).changed == ()


def test_several_files_run_on_several_threads(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"mod_{index}.py").write_text(
            f"def work_{index}(qty):\n    return {{'ok': True}}\n",
            encoding="utf-8",
        )
    report = fix_tree(tmp_path, use_host=False)
    assert report.workers >= 2
    assert (tmp_path / ".vibecleaner" / "origin.json").is_file()
    assert len(report.changed) == 4
    for index in range(4):
        text = (tmp_path / f"mod_{index}.py").read_text(encoding="utf-8")
        assert f"stub: work_{index}" in text
    assert fix_tree(tmp_path, use_host=False).changed == ()


def test_one_rule_can_be_reverted(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def run():\n    breakpoint()\n    return 1\n", encoding="utf-8")
    fix_tree(tmp_path, use_host=False)
    assert "breakpoint" not in (tmp_path / "app.py").read_text(encoding="utf-8")
    revert_rule(tmp_path, "D9.debug_leftover")
    assert "breakpoint()" in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_markdown_tables_lists_logs_and_non_tic_prose_are_preserved(tmp_path: Path) -> None:
    (tmp_path / "WalletService.cs").write_text(
        "public class WalletService { public string SyncEsploraBalance() => \"ok\"; }\n",
        encoding="utf-8",
    )
    readme = (
        "# SatFreedom\n\n"
        "## Screens\n\n"
        "| Screen | Description |\n"
        "|---|---|\n"
        "| Dashboard | Savings progress and balance audit against logged entries |\n"
        "| Wallets | Add, edit, and manage watch addresses for tracking |\n\n"
        "- **Counts toward goal**: Include the wallet balance in the savings target.\n"
        "- **Delete wallet**: Wallets with existing journal entries cannot be deleted.\n\n"
        "Click Edit on any wallet row. The form updates to show current values. "
        "Click Save wallet to apply changes or Cancel to abort.\n\n"
        "This seamless platform unlocks a cutting-edge future for every team.\n"
    )
    papercuts = (
        "# Papercuts\n\n"
        "The first multi-view copy cleanup patch used context from a different file order "
        "and did not apply; split it into one-file patches after reading exact line context.\n\n"
        "This seamless platform unlocks a cutting-edge future.\n"
    )
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    (tmp_path / "PAPERCUTS.md").write_text(papercuts, encoding="utf-8")

    report = fix_tree(tmp_path, use_host=False)
    updated_readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    updated_papercuts = (tmp_path / "PAPERCUTS.md").read_text(encoding="utf-8")

    assert "| Dashboard |" in updated_readme
    assert "- **Counts toward goal**" in updated_readme
    assert "Click Edit on any wallet row." in updated_readme
    assert "seamless platform" not in updated_readme
    assert updated_papercuts == papercuts
    assert report.changed == ("README.md",)

    checkpoint = json.loads((tmp_path / ".vibecleaner" / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["rules"]["README.md"] == ["prose.drop"]

    revert_rule(tmp_path, "prose.drop")
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == readme
