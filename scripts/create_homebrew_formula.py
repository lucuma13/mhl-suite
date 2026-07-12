#!/usr/bin/env python3
"""
Create a Homebrew formula for this package from pyproject.toml and uv.lock.

Package-agnostic: reads project metadata and the locked runtime dependency
closure from the current package, so this script can be ported into any
uv-managed Python repo. Each runtime dependency is either vendored as a
`resource` block built from its sdist, or — if a same-named Homebrew-core
formula exists AND is verified safe — turned into a plain `depends_on`
instead.

"Safe" is checked against the formula's actual source, not just its
existence: Homebrew's `virtualenv_create` only auto-wires a dependency's
modules into the venv (via a generated .pth file) when that dependency's own
formula installs straight into its `opt_prefix`'s top-level
`lib/pythonX.Y/site-packages` — the pattern homebrew-core's `pillow` formula
uses, calling `pip install --prefix=...` itself rather than building an
isolated venv. A same-named formula that instead uses
`virtualenv_install_with_resources` (e.g. homebrew-core's `pygments`) builds
its own isolated venv nested under `libexec`, invisible to a sibling
formula's venv; and a same-named formula with no Python involved at all (e.g.
homebrew-core's `xxhash`, a C CLI/library sharing a name with the PyPI
`xxhash` bindings) provides no importable module whatsoever. Both would
silently compile into a `depends_on` that never actually satisfies the
runtime import, so `homebrew_provides_module()` fetches the formula's .rb
source from GitHub and only signs off when it depends on a Homebrew `python@`
formula and does NOT include `Language::Python::Virtualenv`.

Per-repo extras — system libraries a dependency needs at build time (e.g.
`libheif:build`) or external CLI tools the package shells out to at runtime
— are declared in pyproject.toml as:

    [tool.<project-name>]
    homebrew.dependencies = [ "ffmpeg" ]

A bare name is a plain (build+runtime) `depends_on`; suffix with `:build` or
`:test` to scope it to that stage only.

Usage:
    create_homebrew_formula.py [--repo OWNER/NAME] [--tag TAG] [--output-dir DIR] [--root DIR]

--repo defaults to the GitHub repo parsed from [project.urls.Homepage], --tag
defaults to [project.version], and --output-dir defaults to <root>/scripts,
so a plain `create_homebrew_formula.py` cuts a formula for the version
currently checked out and drops it next to this script. Pass any of them
explicitly to target a different release or write straight into a tap's
Formula/ directory (which is what the release workflow does).

Prints the generated formula's filename to stdout.
"""

import argparse
import hashlib
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

USER_AGENT = "create_homebrew_formula.py"
HTTP_NOT_FOUND = 404
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$")
PYTHON_DEP_RE = re.compile(r'depends_on\s+"python@')


def repo_from_homepage(homepage: str | None) -> str | None:
    if not homepage:
        return None
    match = GITHUB_REPO_RE.match(homepage)
    return match.group(1) if match else None


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def camel_case(name: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[-_.]+", name) if part)


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return response.read()


def homebrew_provides_module(name: str) -> bool:
    """
    True if Homebrew's `name` formula would satisfy `import <name>`-shaped
    access for a sibling formula's isolated virtualenv. See the module
    docstring for what makes a formula safe versus a false-positive trap.
    """
    try:
        metadata = json.loads(fetch(f"https://formulae.brew.sh/api/formula/{name}.json"))
    except urllib.error.HTTPError as error:
        if error.code == HTTP_NOT_FOUND:
            return False
        raise
    except urllib.error.URLError:
        print(f"warning: could not reach formulae.brew.sh to check '{name}'; vendoring it instead", file=sys.stderr)
        return False

    tap = metadata.get("tap", "")
    ruby_source_path = metadata.get("ruby_source_path")
    owner, _, repo_suffix = tap.partition("/")
    if not owner or not repo_suffix or not ruby_source_path:
        return False

    source_url = f"https://raw.githubusercontent.com/{owner}/homebrew-{repo_suffix}/HEAD/{ruby_source_path}"
    try:
        source = fetch(source_url).decode()
    except (urllib.error.HTTPError, urllib.error.URLError):
        print(f"warning: could not fetch formula source for '{name}'; vendoring it instead", file=sys.stderr)
        return False

    is_isolated_venv = "Language::Python::Virtualenv" in source
    return PYTHON_DEP_RE.search(source) is not None and not is_isolated_venv


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def resolve_runtime_closure(lock: dict[str, Any], root_name: str) -> list[dict[str, Any]]:
    packages = {normalize(pkg["name"]): pkg for pkg in lock["package"]}
    root = packages[root_name]

    closure: list[dict[str, Any]] = []
    seen = {root_name}
    queue = [dep["name"] for dep in root.get("dependencies", [])]
    while queue:
        dep_key = normalize(queue.pop(0))
        if dep_key in seen:
            continue
        seen.add(dep_key)
        dep_pkg = packages.get(dep_key)
        if dep_pkg is None:
            continue
        closure.append(dep_pkg)
        queue.extend(sub["name"] for sub in dep_pkg.get("dependencies", []))

    closure.sort(key=lambda pkg: str(pkg["name"]))
    return closure


def split_runtime_deps(closure: list[dict[str, Any]]) -> tuple[list[str], list[tuple[str, str, str]]]:
    shadowed: list[str] = []
    vendored: list[tuple[str, str, str]] = []
    for dep in closure:
        dep_name = str(dep["name"])
        if homebrew_provides_module(dep_name):
            shadowed.append(dep_name)
            continue
        sdist = dep.get("sdist")
        if sdist is None:
            print(f"warning: '{dep_name}' has no sdist in the lockfile; skipping (build may fail)", file=sys.stderr)
            continue
        vendored.append((dep_name, sdist["url"], sdist["hash"].removeprefix("sha256:")))
    return shadowed, vendored


def latest_supported_python(classifiers: list[str]) -> str:
    pattern = re.compile(r"Programming Language :: Python :: (\d+\.\d+)$")
    versions = sorted(
        (m.group(1) for c in classifiers if (m := pattern.match(c))),
        key=lambda v: tuple(int(part) for part in v.split(".")),
    )
    if not versions:
        raise ValueError("no 'Programming Language :: Python :: X.Y' classifiers found")
    return versions[-1]


def license_text(project: dict[str, Any]) -> str | None:
    license_field = project.get("license")
    if isinstance(license_field, dict):
        return license_field.get("text")
    if isinstance(license_field, str):
        return license_field
    return None


@dataclass
class FormulaSpec:
    class_name: str
    desc: str
    homepage: str
    tarball_url: str
    tarball_sha256: str
    license_value: str | None
    system_deps: list[str]
    shadowed_deps: list[str]
    python_version: str
    vendored_deps: list[tuple[str, str, str]]
    scripts: list[str]


def _depends_on_line(entry: str) -> str:
    name, _, kind = entry.partition(":")
    return f'  depends_on "{name}" => :{kind}' if kind else f'  depends_on "{name}"'


def _order_system_deps(system_deps: list[str]) -> list[str]:
    # Homebrew's DependencyOrder style wants build-/test-only deps listed before plain ones.
    return sorted(system_deps, key=lambda entry: 0 if ":" in entry else 1)


def render_formula(spec: FormulaSpec) -> str:
    lines = [f"class {spec.class_name} < Formula", "  include Language::Python::Virtualenv", ""]
    lines.append(f'  desc "{spec.desc.replace(chr(34), chr(92) + chr(34))}"')
    lines.append(f'  homepage "{spec.homepage}"')
    lines.append(f'  url "{spec.tarball_url}"')
    lines.append(f'  sha256 "{spec.tarball_sha256}"')
    if spec.license_value:
        lines.append(f'  license "{spec.license_value}"')
    lines.append("")

    lines.extend(_depends_on_line(entry) for entry in _order_system_deps(spec.system_deps))
    lines.extend(f'  depends_on "{name}"' for name in spec.shadowed_deps)
    lines.append(f'  depends_on "python@{spec.python_version}"')
    lines.append("")

    for name, url, sha256 in spec.vendored_deps:
        lines.append(f'  resource "{name}" do')
        lines.append(f'    url "{url}"')
        lines.append(f'    sha256 "{sha256}"')
        lines.append("  end")
        lines.append("")

    lines.append("  def install")
    lines.append("    virtualenv_install_with_resources")
    lines.append("  end")
    lines.append("")
    lines.append("  test do")
    lines.extend(f'    assert_match version.to_s, shell_output("#{{bin}}/{cmd} --version")' for cmd in spec.scripts)
    lines.append("  end")
    lines.append("end")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="GitHub 'owner/name' the release tag lives in (default: parsed from Homepage)")
    parser.add_argument("--tag", help="Release tag to point the formula at (default: [project.version])")
    parser.add_argument("--output-dir", type=Path, help="Directory to write into (default: <root>/scripts)")
    parser.add_argument("--root", type=Path, help="Package root (default: this script's repo root)")
    args = parser.parse_args()
    root = args.root or Path(__file__).resolve().parent.parent
    output_dir = args.output_dir or (root / "scripts")

    pyproject = load_toml(root / "pyproject.toml")
    lock = load_toml(root / "uv.lock")
    project = pyproject["project"]

    package_name = str(project["name"])
    normalized_name = normalize(package_name)

    homepage = project.get("urls", {}).get("Homepage")
    repo = args.repo or repo_from_homepage(homepage)
    if not repo:
        parser.error("--repo not given and no GitHub URL found in [project.urls.Homepage]")

    tag = args.tag or project.get("version")
    if not tag:
        parser.error("--tag not given and no [project.version] found in pyproject.toml")

    # Hash the release tarball before resolving the closure: it is the one step
    # that depends on the tag actually being pushed, and the closure costs a
    # network round-trip per dependency.
    tarball_url = f"https://github.com/{repo}/archive/refs/tags/{tag}.tar.gz"
    try:
        tarball_sha256 = hashlib.sha256(fetch(tarball_url)).hexdigest()
    except urllib.error.HTTPError as error:
        if error.code != HTTP_NOT_FOUND:
            raise
        sys.exit(
            f"error: no release tarball at {tarball_url}\n"
            f"       Tag '{tag}' does not exist on {repo}. Push the tag (or pass an\n"
            f"       existing one with --tag) before cutting a formula for it."
        )

    closure = resolve_runtime_closure(lock, normalized_name)
    shadowed_deps, vendored_deps = split_runtime_deps(closure)

    homepage = homepage or f"https://github.com/{repo}"
    homebrew_config = pyproject.get("tool", {}).get(package_name, {}).get("homebrew", {})
    system_deps = homebrew_config.get("dependencies", [])

    formula = render_formula(
        FormulaSpec(
            class_name=camel_case(package_name),
            desc=str(project.get("description", "")),
            homepage=homepage,
            tarball_url=tarball_url,
            tarball_sha256=tarball_sha256,
            license_value=license_text(project),
            system_deps=system_deps,
            shadowed_deps=shadowed_deps,
            python_version=latest_supported_python(project.get("classifiers", [])),
            vendored_deps=vendored_deps,
            scripts=list(project.get("scripts", {}).keys()),
        )
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    formula_path = output_dir / f"{normalized_name}.rb"
    formula_path.write_text(formula)
    print(formula_path.name)


if __name__ == "__main__":
    main()
