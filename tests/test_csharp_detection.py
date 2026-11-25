"""C# / .NET language, runtime, gate, and stack detection."""

from __future__ import annotations

from pathlib import Path

from vibecleaner.collector import collect
from vibecleaner.models import Language
from vibecleaner.preflight.engine import run_preflight
from vibecleaner.verify.files import has_code, is_config_path, is_test_path, language_for, project_runtimes
from vibecleaner.verify.gates import detect_gates
from vibecleaner.verify.sandbox import choose_image


def test_csharp_detected_across_collector_verify_sandbox_gates_and_preflight(tmp_path: Path) -> None:
    (tmp_path / "App").mkdir()
    (tmp_path / "App" / "App.csproj").write_text(
        "<Project Sdk=\"Microsoft.NET.Sdk.Web\">\n  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>\n</Project>\n",
        encoding="utf-8",
    )
    (tmp_path / "App" / "Program.cs").write_text(
        "using System;\nnamespace Demo;\npublic class Program { public static void Main() => Console.WriteLine(\"hi\"); }\n",
        encoding="utf-8",
    )
    (tmp_path / "App" / "OrderServiceTests.cs").write_text(
        "namespace Demo.Tests;\npublic class OrderServiceTests {}\n",
        encoding="utf-8",
    )

    ctx = collect(tmp_path)
    by_path = {sf.path: sf for sf in ctx.files}
    assert by_path["App/Program.cs"].language == Language.CSHARP
    assert language_for("App/Program.cs") == Language.CSHARP
    assert is_test_path("App/OrderServiceTests.cs") is True
    assert is_test_path("App/Program.cs") is False
    assert is_config_path("App/App.csproj") is True
    assert has_code(tmp_path) is True
    assert "csharp" in project_runtimes(tmp_path)
    assert "dotnet/sdk" in choose_image(tmp_path)
    gates = detect_gates(tmp_path)
    assert any(g.name == "dotnet" and g.language == "csharp" for g in gates)
    preflight = run_preflight(ctx, [])
    assert "C# / .NET" in preflight.stack


def test_non_csharp_repo_does_not_detect_csharp(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Notes\nJust prose.\n", encoding="utf-8")
    assert language_for("README.md") is None
    assert "csharp" not in project_runtimes(tmp_path)
    preflight = run_preflight(collect(tmp_path), [])
    assert "C# / .NET" not in preflight.stack


def test_csharp_scan_coverage_and_preflight_checks(tmp_path: Path) -> None:
    from io import StringIO
    from rich.console import Console
    from vibecleaner.pipeline import run_scan
    from vibecleaner.preflight.results import Status
    from vibecleaner.reporter import render_terminal, to_json

    (tmp_path / "App.Api").mkdir()
    (tmp_path / "App.Api" / "App.Api.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>\n',
        encoding="utf-8",
    )
    (tmp_path / "App.Api" / "Program.cs").write_text(
        "var builder = WebApplication.CreateBuilder(args);\n"
        "builder.Services.AddDbContext<AppDb>(o => o.UseSqlite(\"Data Source=app.db\"));\n"
        "var app = builder.Build();\n"
        "app.MapGet(\"/api/items\", () => Results.Ok());\n",
        encoding="utf-8",
    )
    (tmp_path / "App.Tests").mkdir()
    (tmp_path / "App.Tests" / "ItemTests.cs").write_text(
        "public class ItemTests { public void Works() {} }\n",
        encoding="utf-8",
    )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "dotnet.yml").write_text("jobs:\n  test:\n    steps:\n      - run: dotnet test\n", encoding="utf-8")

    result, ctx = run_scan(tmp_path, mode="off", use_cache=False)
    assert result.supported_code_files == 0
    assert result.unsupported_code_files == {".cs": 2}

    payload = to_json(result)
    assert payload["coverage"] == {"supported_code_files": 0, "unsupported_code_files": {".cs": 2}}

    buf = StringIO()
    render_terminal(result, Console(file=buf, force_terminal=False, width=120))
    rendered = buf.getvalue()
    assert "coverage warning" in rendered
    assert "PARTIAL" in rendered

    preflight = run_preflight(ctx, result.findings)
    checks = {c.id: c for c in preflight.checks}
    assert checks[30].status == Status.OK
    assert checks[11].status != Status.NOT_APPLICABLE
    assert "dotnet list package --vulnerable" in checks[11].verify
    assert checks[26].status != Status.NOT_APPLICABLE
