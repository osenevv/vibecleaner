"""Detect the project's own checks and run them in the sandbox."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import sys
from pathlib import Path

from vibecleaner.fix_contract import CheckResult, Evidence, EvidenceKind, ExecResult, FixContext, Verdict
from vibecleaner.verify.config_text import dig, load_ini, load_json, load_toml, requirement_name, requirement_names
from vibecleaner.verify.failures import parse_failures
from vibecleaner.models import Language
from vibecleaner.verify.files import has_code, iter_files, language_for, read_text
from vibecleaner.verify.gate import Gate

_GATE_TIMEOUT_S = 120
_INSTALL_TIMEOUT_S = 180
_CONTAINER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_PY_PROJECT_FILES = ("pyproject.toml", "setup.py", "setup.cfg")
_DEP_FILES = (
    "Pipfile.lock",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "uv.lock",
    "yarn.lock",
    "npm-shrinkwrap.json",
)

_PYTEST = Gate(
    "pytest",
    EvidenceKind.TEST_FAILURE,
    ("python", "-m", "pytest", "-q", "-x"),
    "python",
    (("pytest", "-q", "-x"), ("py.test", "-q")),
)
_DJANGO = Gate(
    "django",
    EvidenceKind.TEST_FAILURE,
    ("python", "manage.py", "test", "--noinput"),
    "python",
    (("python3", "manage.py", "test", "--noinput"),),
)
_RUFF = Gate("ruff", EvidenceKind.LINT_ERROR, ("ruff", "check", "."), "python", (("python", "-m", "ruff", "check", "."),))
_MYPY = Gate("mypy", EvidenceKind.TYPE_ERROR, ("mypy", "."), "python", (("python", "-m", "mypy", "."),))
_PYRIGHT = Gate("pyright", EvidenceKind.TYPE_ERROR, ("pyright",), "python", (("npx", "pyright"),))
_TSC = Gate("tsc", EvidenceKind.TYPE_ERROR, ("tsc", "--noEmit"), "typescript", (("npx", "tsc", "--noEmit"),))
_ESLINT = Gate("eslint", EvidenceKind.LINT_ERROR, ("eslint", "."), "javascript", (("npx", "eslint", "."),))
_VITEST = Gate("vitest", EvidenceKind.TEST_FAILURE, ("vitest", "run"), "typescript", (("npx", "vitest", "run"), ("pnpm", "exec", "vitest", "run")))
_JEST = Gate(
    "jest",
    EvidenceKind.TEST_FAILURE,
    ("jest", "--watchAll=false"),
    "javascript",
    (("npx", "jest", "--watchAll=false"), ("yarn", "jest", "--watchAll=false")),
)
_CONFIG_COMMANDS = (
    ("test", EvidenceKind.TEST_FAILURE),
    ("lint", EvidenceKind.LINT_ERROR),
    ("typecheck", EvidenceKind.TYPE_ERROR),
    ("build", EvidenceKind.BUILD_ERROR),
)
_MAKE_RULE = re.compile(r"^([^\s:#][^:#]*?)\s*:(?!=)")
_RSPEC = re.compile(r"\brspec\b", re.IGNORECASE)


def detect_gates(root: Path) -> list[Gate]:
    root = Path(root)
    if not root.is_dir():
        return []
    overrides = _config_gates(root)
    overridden = {gate.kind for gate in overrides}
    detected = [gate for gate in _language_gates(root) if gate.kind not in overridden]
    if not any(gate.kind is EvidenceKind.TEST_FAILURE for gate in (*overrides, *detected)):
        makefile = _make_test_gate(root)
        if makefile is not None:
            detected.append(makefile)
    return [*overrides, *detected]


def run_gates(ctx: FixContext, cwd: Path, gates: list[Gate] | None = None) -> CheckResult:
    root = _resolve_cwd(ctx.root, cwd)
    chosen = detect_gates(root) if gates is None else list(gates)
    if not chosen:
        if has_code(root):
            note = Evidence(
                kind=EvidenceKind.JUDGE_NOTE,
                summary="no test, type, or lint gate detected",
            )
            return CheckResult(node="execution_gate", verdict=Verdict.ESCALATE, notes=(note,))
        return CheckResult(node="execution_gate", verdict=Verdict.PASS)
    ctx.progress("Running your tests")
    install_error = ensure_dependencies(ctx, root)
    if install_error is not None:
        return CheckResult(node="execution_gate", verdict=Verdict.REVISE, evidence=(install_error,))
    env = tool_env(ctx.sandbox.name, root)
    failures: list[Evidence] = []
    for gate in chosen:
        result = _run_attempt(ctx, root, gate, env)
        if result is None or result.ok:
            continue
        failures.extend(parse_failures(gate, result))
    if failures:
        return CheckResult(node="execution_gate", verdict=Verdict.REVISE, evidence=tuple(failures))
    return CheckResult(node="execution_gate", verdict=Verdict.PASS)


def _run_attempt(ctx: FixContext, root: Path, gate: Gate, env: dict[str, str]) -> ExecResult | None:
    """Try each spelling. A missing binary is not a failure while another spelling remains."""
    last: ExecResult | None = None
    for command in gate.attempts():
        last = ctx.sandbox.run(
            command,
            cwd=root,
            timeout_s=_GATE_TIMEOUT_S,
            network=False,
            env=env or None,
        )
        if last.ok or not _command_missing(last):
            return last
    return last


def _command_missing(result: ExecResult) -> bool:
    if result.timed_out or result.returncode != 127:
        return False
    return True


def ensure_dependencies(ctx: FixContext, root: Path) -> Evidence | None:
    digest = dependency_hash(root)
    if digest is None:
        return None
    cache = root / ".vibecleaner" / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    marker = cache / f"deps-{ctx.sandbox.name}-{digest}.ok"
    if marker.is_file():
        return None
    for stale in cache.glob(f"deps-{ctx.sandbox.name}-*.ok"):
        stale.unlink(missing_ok=True)
    env = _install_env(ctx.sandbox.name, root)
    for command in _install_commands(ctx.sandbox.name, root):
        result = ctx.sandbox.run(
            command,
            cwd=root,
            timeout_s=_INSTALL_TIMEOUT_S,
            network=True,
            env=env,
        )
        if not result.ok:
            return _install_evidence(command, result)
    marker.write_text(digest, encoding="utf-8")
    return None


def dependency_hash(root: Path) -> str | None:
    hasher = hashlib.sha256()
    found = False
    for name in _DEP_FILES:
        path = root / name
        if not path.is_file():
            continue
        found = True
        hasher.update(name.encode())
        hasher.update(path.read_bytes())
    for path in sorted(root.glob("requirements*.txt")):
        if path.name in _DEP_FILES:
            continue
        found = True
        hasher.update(path.name.encode())
        hasher.update(path.read_bytes())
    if not found:
        return None
    return hasher.hexdigest()[:16]


def tool_env(sandbox_name: str, root: Path) -> dict[str, str]:
    prefixes: list[str] = []
    venv_bin = root / ".vibecleaner" / "cache" / f"venv-{sandbox_name}" / "bin"
    project_venv_bin = root / ".venv" / "bin"
    node_bin = root / "node_modules" / ".bin"
    if venv_bin.is_dir():
        prefixes.append(str(venv_bin))
    if sandbox_name == "host" and project_venv_bin.is_dir():
        prefixes.append(str(project_venv_bin))
    if node_bin.is_dir():
        prefixes.append(str(node_bin))
    if not prefixes:
        return {}
    base = os.environ.get("PATH", "") if sandbox_name == "host" else _CONTAINER_PATH
    return {"PATH": ":".join([*prefixes, base]) if base else ":".join(prefixes)}


def _python_gates(root: Path) -> list[Gate]:
    names = _python_dependency_names(root)
    text = read_text(root / "pyproject.toml") or ""
    data = load_toml(text) if text else {}
    setup = read_text(root / "setup.cfg") or ""
    ini = load_ini(setup) if setup else None
    gates: list[Gate] = []
    if _wants_ruff(root, names, data):
        gates.append(_RUFF)
    if _wants_mypy(root, names, data, ini):
        gates.append(_MYPY)
    if _wants_pyright(root, names, data):
        gates.append(_PYRIGHT)
    if _wants_pytest(root, names, data, ini):
        gates.append(_PYTEST)
    elif "django" in names and (root / "manage.py").is_file():
        gates.append(_DJANGO)
    return gates


def _js_gates(root: Path) -> list[Gate]:
    package_text = read_text(root / "package.json") or ""
    package = load_json(package_text) if package_text else {}
    deps = _js_deps(package)
    scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
    language = _js_language(root, deps)
    gates: list[Gate] = []
    if (root / "tsconfig.json").is_file() or "typescript" in deps:
        gates.append(_with_language(_TSC, language))
    if _wants_eslint(root, deps, package):
        gates.append(_with_language(_ESLINT, language))
    test_gate = _js_test_gate(root, package, deps, scripts, language)
    if test_gate is not None:
        gates.append(test_gate)
    return gates


def _wants_pytest(root: Path, names: set[str], data: dict[str, object], ini: object) -> bool:
    if "pytest" in names:
        return True
    if dig(data, "tool", "pytest") is not None:
        return True
    if (root / "pytest.ini").is_file() or (root / "tox.ini").is_file():
        return True
    return _ini_has(ini, "tool:pytest")


def _wants_ruff(root: Path, names: set[str], data: dict[str, object]) -> bool:
    if "ruff" in names or dig(data, "tool", "ruff") is not None:
        return True
    return (root / "ruff.toml").is_file() or (root / ".ruff.toml").is_file()


def _wants_mypy(root: Path, names: set[str], data: dict[str, object], ini: object) -> bool:
    if "mypy" in names or dig(data, "tool", "mypy") is not None:
        return True
    if (root / "mypy.ini").is_file():
        return True
    return _ini_has(ini, "mypy")


def _wants_pyright(root: Path, names: set[str], data: dict[str, object]) -> bool:
    if "pyright" in names or dig(data, "tool", "pyright") is not None:
        return True
    return (root / "pyrightconfig.json").is_file()


def _wants_eslint(root: Path, deps: set[str], package: dict[str, object]) -> bool:
    if "eslint" in deps or "eslintConfig" in package:
        return True
    return any((root / name).is_file() for name in (
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yaml",
        ".eslintrc.yml",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        "eslint.config.ts",
    ))


def _js_test_gate(
    root: Path,
    package: dict[str, object],
    deps: set[str],
    scripts: object,
    language: str,
) -> Gate | None:
    script_map = scripts if isinstance(scripts, dict) else {}
    uses_vitest = _script_uses(script_map, "vitest")
    uses_jest = _script_uses(script_map, "jest")
    has_vitest = "vitest" in deps or uses_vitest or _config_exists(root, "vitest.config.")
    has_jest = "jest" in deps or "jest" in package or uses_jest or _config_exists(root, "jest.config.")
    if uses_vitest and not uses_jest:
        has_jest = False
    elif uses_jest and not uses_vitest:
        has_vitest = False
    elif has_vitest and has_jest:
        has_jest = False
    if has_vitest:
        return _with_language(_VITEST, language)
    if has_jest:
        return _with_language(_JEST, language)
    return None


def _python_dependency_names(root: Path) -> set[str]:
    names: set[str] = set()
    text = read_text(root / "pyproject.toml")
    if text:
        names.update(_toml_deps(load_toml(text)))
    setup = read_text(root / "setup.cfg")
    if setup:
        names.update(_setup_cfg_deps(setup))
    for path in sorted(root.glob("requirements*.txt")):
        body = read_text(path)
        if body:
            names.update(requirement_names(body))
    return names


def _toml_deps(data: dict[str, object]) -> set[str]:
    names: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        names.update(_string_reqs(project.get("dependencies")))
        extras = project.get("optional-dependencies")
        if isinstance(extras, dict):
            for group in extras.values():
                names.update(_string_reqs(group))
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            names.update(_string_reqs(group))
    poetry = dig(data, "tool", "poetry", "dependencies")
    if isinstance(poetry, dict):
        names.update(requirement_name(key) for key in poetry if key != "python")
    group_table = dig(data, "tool", "poetry", "group")
    if isinstance(group_table, dict):
        for group in group_table.values():
            if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                names.update(requirement_name(key) for key in group["dependencies"])
    return {name for name in names if name}


def _setup_cfg_deps(text: str) -> set[str]:
    parser = load_ini(text)
    names: set[str] = set()
    if parser.has_option("options", "install_requires"):
        names.update(requirement_names(parser.get("options", "install_requires")))
    if parser.has_section("options.extras_require"):
        for _key, value in parser.items("options.extras_require"):
            names.update(requirement_names(value))
    return names


def _string_reqs(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {requirement_name(item) for item in value if isinstance(item, str)}


def _js_deps(package: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        table = package.get(key)
        if isinstance(table, dict):
            names.update(str(name) for name in table)
    return names


def _js_language(root: Path, deps: set[str]) -> str:
    if "typescript" in deps or (root / "tsconfig.json").is_file():
        return "typescript"
    for rel, _path in iter_files(root):
        if language_for(rel) in {Language.TYPESCRIPT, Language.TSX}:
            return "typescript"
    return "javascript"


def _script_uses(scripts: dict[object, object], tool: str) -> bool:
    pattern = tool
    for value in scripts.values():
        if not isinstance(value, str):
            continue
        for token in value.replace("/", " ").split():
            if token == pattern or token.endswith(f"/{pattern}"):
                return True
    return False


def _config_exists(root: Path, prefix: str) -> bool:
    return any(path.name.startswith(prefix) for path in root.iterdir() if path.is_file())


def _ini_has(parser: object, section: str) -> bool:
    has_section = getattr(parser, "has_section", None)
    return bool(has_section is not None and has_section(section))


def _with_language(gate: Gate, language: str) -> Gate:
    if gate.language == language:
        return gate
    return Gate(gate.name, gate.kind, gate.command, language, gate.alts)


def _install_commands(sandbox_name: str, root: Path) -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = []
    if _has_python_project(root):
        venv = root / ".vibecleaner" / "cache" / f"venv-{sandbox_name}"
        venv_python = venv / "bin" / "python"
        if venv.exists():
            shutil.rmtree(venv)
        launcher = sys.executable if sandbox_name == "host" else "python"
        commands.append((launcher, "-m", "venv", str(venv)))
        if any((root / name).is_file() for name in _PY_PROJECT_FILES):
            commands.append((str(venv_python), "-m", "pip", "install", "-e", str(root)))
        for req in sorted(root.glob("requirements*.txt")):
            commands.append((str(venv_python), "-m", "pip", "install", "-r", str(req)))
    if (root / "package.json").is_file():
        cache = str(root / ".vibecleaner" / "cache" / "npm")
        if (root / "package-lock.json").is_file() or (root / "npm-shrinkwrap.json").is_file():
            commands.append(("npm", "ci", "--cache", cache))
        else:
            commands.append(("npm", "install", "--cache", cache))
    return commands


def _has_python_project(root: Path) -> bool:
    if any((root / name).is_file() for name in _PY_PROJECT_FILES):
        return True
    return any(root.glob("requirements*.txt"))


def _install_env(sandbox_name: str, root: Path) -> dict[str, str]:
    env = tool_env(sandbox_name, root)
    cache = root / ".vibecleaner" / "cache"
    env["PIP_CACHE_DIR"] = str(cache / "pip")
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    if sandbox_name == "host":
        base = os.environ.get("PATH", "")
        if "PATH" not in env and base:
            env["PATH"] = base
    return env


def _install_evidence(command: tuple[str, ...], result: ExecResult) -> Evidence:
    text = result.stdout if not result.stderr else f"{result.stdout}\n{result.stderr}"
    summary = next((line.strip() for line in text.splitlines() if line.strip()), "dependency install failed")
    if result.timed_out:
        summary = "dependency install timed out"
    return Evidence(
        kind=EvidenceKind.BUILD_ERROR,
        summary=summary[:300],
        command=command,
        output=text,
    )


def _resolve_cwd(root: Path, cwd: Path) -> Path:
    path = Path(cwd)
    if not path.is_absolute():
        return (Path(root) / path).resolve()
    return path.resolve()


def _language_gates(root: Path) -> list[Gate]:
    gates = _python_gates(root)
    gates.extend(_js_gates(root))
    if any(gate.kind is EvidenceKind.TEST_FAILURE for gate in gates):
        return gates
    extra = _ecosystem_test_gate(root)
    if extra is not None:
        gates.append(extra)
    return gates


def _config_gates(root: Path) -> list[Gate]:
    text = read_text(root / ".vibecleaner" / "config.json")
    if not text:
        return []
    data = load_json(text)
    gates: list[Gate] = []
    for key, kind in _CONFIG_COMMANDS:
        if key not in data:
            continue
        command = _split_command(data[key])
        if not command:
            continue
        gates.append(Gate(key, kind, command, "config"))
    return gates


def _split_command(value: object) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    try:
        parts = shlex.split(value, posix=True)
    except ValueError:
        return ()
    return tuple(parts)


def _ecosystem_test_gate(root: Path) -> Gate | None:
    for detect in (
        _go_test_gate,
        _cargo_test_gate,
        _jvm_test_gate,
        _dotnet_test_gate,
        _ruby_test_gate,
        _php_test_gate,
        _mix_test_gate,
    ):
        gate = detect(root)
        if gate is not None:
            return gate
    return None


def _go_test_gate(root: Path) -> Gate | None:
    if (root / "go.mod").is_file():
        return Gate("go", EvidenceKind.TEST_FAILURE, ("go", "test", "./..."), "go", (("go", "test", "."),))
    return None


def _cargo_test_gate(root: Path) -> Gate | None:
    if (root / "Cargo.toml").is_file():
        return Gate("cargo", EvidenceKind.TEST_FAILURE, ("cargo", "test"), "rust", (("cargo", "test", "--workspace"),))
    return None


def _jvm_test_gate(root: Path) -> Gate | None:
    if (root / "gradlew").is_file():
        return Gate("gradle", EvidenceKind.TEST_FAILURE, ("./gradlew", "test"), "java", (("gradle", "test"),))
    if (root / "build.gradle").is_file() or (root / "build.gradle.kts").is_file():
        return Gate("gradle", EvidenceKind.TEST_FAILURE, ("gradle", "test"), "java")
    if (root / "pom.xml").is_file():
        return Gate("mvn", EvidenceKind.TEST_FAILURE, ("mvn", "-q", "test"), "java", (("./mvnw", "-q", "test"), ("mvn", "test")))
    return None


def _dotnet_test_gate(root: Path) -> Gate | None:
    patterns = ("*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*/*.csproj")
    if any(any(root.glob(pattern)) for pattern in patterns):
        return Gate("dotnet", EvidenceKind.TEST_FAILURE, ("dotnet", "test"), "csharp")
    return None


def _ruby_test_gate(root: Path) -> Gate | None:
    gemfile = read_text(root / "Gemfile") or ""
    if gemfile and _uses_rspec(root, gemfile):
        return Gate("rspec", EvidenceKind.TEST_FAILURE, ("bundle", "exec", "rspec"), "ruby", (("rspec",),))
    if (root / "Rakefile").is_file() or (root / "rakefile").is_file():
        return Gate("rake", EvidenceKind.TEST_FAILURE, ("rake", "test"), "ruby")
    return None


def _uses_rspec(root: Path, gemfile: str) -> bool:
    if _RSPEC.search(gemfile):
        return True
    if (root / ".rspec").is_file():
        return True
    return (root / "spec").is_dir()


def _php_test_gate(root: Path) -> Gate | None:
    text = read_text(root / "composer.json") or ""
    data = load_json(text) if text else {}
    scripts = data.get("scripts")
    table = scripts if isinstance(scripts, dict) else {}
    if _script_present(table.get("test")):
        return Gate("composer", EvidenceKind.TEST_FAILURE, ("composer", "test"), "php", (("composer", "run", "test"),))
    if _has_phpunit(root, data):
        return Gate("phpunit", EvidenceKind.TEST_FAILURE, ("vendor/bin/phpunit",), "php", (("phpunit",),))
    return None


def _script_present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(isinstance(item, str) and item.strip() for item in value)
    return False


def _has_phpunit(root: Path, data: dict[str, object]) -> bool:
    names = ("phpunit.xml", "phpunit.xml.dist")
    if any((root / name).is_file() for name in names):
        return True
    if (root / "vendor" / "bin" / "phpunit").is_file():
        return True
    for key in ("require", "require-dev"):
        deps = data.get(key)
        if isinstance(deps, dict) and any("phpunit" in str(name).lower() for name in deps):
            return True
    return False


def _mix_test_gate(root: Path) -> Gate | None:
    if (root / "mix.exs").is_file():
        return Gate("mix", EvidenceKind.TEST_FAILURE, ("mix", "test"), "elixir")
    return None


def _make_test_gate(root: Path) -> Gate | None:
    for name in ("Makefile", "makefile", "GNUmakefile"):
        text = read_text(root / name)
        if not text:
            continue
        targets = [target for target in ("test", "check", "ci") if _makefile_defines(text, target)]
        if not targets:
            continue
        alts = tuple(("make", target) for target in targets[1:])
        return Gate("make", EvidenceKind.TEST_FAILURE, ("make", targets[0]), "make", alts)
    return None


def _makefile_defines(text: str, target: str) -> bool:
    for line in text.splitlines():
        if not line or line[0].isspace() or line[0] == "#":
            continue
        match = _MAKE_RULE.match(line)
        if match and target in match.group(1).split():
            return True
    return False
