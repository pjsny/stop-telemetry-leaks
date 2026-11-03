#!/usr/bin/env python3
"""Grade one eval iteration produced by prepare.py and agent runs.

Usage: python3 evals/score.py ITERATION_DIR [--fixtures evals/fixtures] [--no-pristine]

Per run (ITERATION_DIR/eval-<fixture>/<mode>/) writes grading.json; per iteration writes
benchmark.json. Each run is scored on:
  - EVAL_RESULT.json entries matched to expected.toml plants (same file, line within 3 of the line
    holding the plant's `match` text in the original fixture);
  - an objective rerun of the final tree (no .git) with the hidden canary tests added, through
    evals/harness/canary_run.py and scan_telemetry.py with seed evalseed42;
  - the repo's own tests, raw secrets in outputs, and the git branch state.
Also reruns the untouched fixture as a `pristine` baseline (ITERATION_DIR/pristine/<fixture>/).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HARNESS = REPO_ROOT / "evals" / "harness"
CANARY_TESTS = REPO_ROOT / "evals" / "canary_tests"
SEED = "evalseed42"
LINE_TOLERANCE = 3
TIMEOUT = 900

sys.path.insert(0, str(HARNESS))
from otelpii.canary import find_canaries  # noqa: E402


@dataclass(frozen=True)
class Rerun:
    lang: str
    bootstrap: str | None
    canary_cmd: list[str]
    test_cmd: list[str]


RERUNS = {
    "py-fastapi-pytest": Rerun("python", None, [".venv/bin/pytest", "-q", "-p", "no:cacheprovider"],
                               [".venv/bin/pytest", "-q", "-p", "no:cacheprovider"]),
    "js-express-vitest": Rerun("node", "./instrumentation.mjs", ["npm", "test", "--silent"],
                               ["npm", "test", "--silent"]),
    "js-fastify-jest": Rerun("node", "./instrumentation.js", ["node", "canary-driver.cjs"],
                             ["npm", "test", "--silent"]),
}
CLEAN_ENV_DROP = ("PYTHONPATH", "VIRTUAL_ENV", "NODE_OPTIONS", "PYTEST_ADDOPTS")


def clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in CLEAN_ENV_DROP}


def load_plants(fixture: Path) -> tuple[list[dict], list[dict]]:
    data = tomllib.loads((fixture / "expected.toml").read_text())
    plants = data.get("plant", [])
    for p in plants:
        p["line"] = planted_line(fixture / p["file"], p["match"])
    return plants, data.get("negative", [])


def planted_line(path: Path, match: str) -> int | None:
    for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if match in line:
            return i
    text = path.read_text(errors="replace")
    pos = text.find(match)
    return None if pos < 0 else text.count("\n", 0, pos) + 1


def load_results(repo: Path) -> tuple[list[dict] | None, str]:
    path = repo / "EVAL_RESULT.json"
    if not path.is_file():
        return None, "EVAL_RESULT.json missing"
    try:
        data = json.loads(path.read_text())
    except ValueError as exc:
        return None, f"EVAL_RESULT.json is not JSON: {exc}"
    if not isinstance(data, list):
        return None, "EVAL_RESULT.json is not a list"
    return [e for e in data if isinstance(e, dict)], f"{len(data)} entries"


def entry_matches(entry: dict, file: str, line: int | None) -> bool:
    if str(entry.get("file", "")).removeprefix("./") != file or line is None:
        return False
    try:
        return abs(int(entry.get("line")) - line) <= LINE_TOLERANCE
    except (TypeError, ValueError):
        return False


def match_plants(plants: list[dict], negatives: list[dict], entries: list[dict]) -> dict:
    matched: dict[str, list[dict]] = {}
    used: set[int] = set()
    for p in plants:
        hits = [(i, e) for i, e in enumerate(entries) if entry_matches(e, p["file"], p["line"])]
        matched[p["id"]] = [e for _, e in hits]
        used.update(i for i, _ in hits)
    false_pos = []
    for n in negatives:
        false_pos += [e for e in entries if entry_matches(e, n.get("file", ""), n.get("line"))]
    unmatched = [e for i, e in enumerate(entries) if i not in used]
    return {"by_plant": matched, "unmatched": unmatched, "negative_hits": false_pos}


def copy_tree(src: Path, dest: Path, fixture: Path) -> Path:
    """Copy `src` without .git or EVAL_RESULT.json; deps link to the original fixture's installs."""
    if dest.exists():
        shutil.rmtree(dest)
    ignore = shutil.ignore_patterns(".git", "EVAL_RESULT.json", "expected.toml", "node_modules", ".venv",
                                    ".pytest_cache", "__pycache__")
    shutil.copytree(src, dest, symlinks=True, ignore=ignore)
    for d in ("node_modules", ".venv"):
        if (fixture / d).is_dir():
            (dest / d).symlink_to((fixture / d).resolve(), target_is_directory=True)
    return dest


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, env=clean_env(), capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, str(exc.stdout or ""), f"timeout after {TIMEOUT}s")


def string_values(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        obj = list(obj.values())
    return [s for item in obj for s in string_values(item)] if isinstance(obj, list) else []


def rerun(name: str, tree: Path, fixture: Path, work: Path) -> dict:
    """Run the repo's tests, then the canary run + scan, on a copy of `tree`. Returns metrics."""
    spec = RERUNS[name]
    copy = copy_tree(tree, work / "tree", fixture)
    tests = run(spec.test_cmd, copy)
    (work / "tests.log").write_text(tests.stdout + tests.stderr)
    shutil.copytree(CANARY_TESTS / name, copy, dirs_exist_ok=True)
    out = work / "canary"
    if out.exists():
        shutil.rmtree(out)
    args = [sys.executable, str(HARNESS / "canary_run.py"), "--lang", spec.lang, "--out-dir", str(out),
            "--seed", SEED, "--cwd", str(copy)]
    if spec.bootstrap:
        args += ["--bootstrap", spec.bootstrap]
    canary = run([*args, "--", *spec.canary_cmd], copy)
    (work / "canary.log").write_text(canary.stdout + canary.stderr)
    capture = out / "capture.jsonl"
    token_hits = pii_hits = 0
    if capture.is_file():
        # Token hits: captured string values holding the token. PII hits: (value, PII kind) pairs.
        for line in capture.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            for value in string_values(json.loads(line)):
                kinds = find_canaries(value, SEED)
                token_hits += "token" in kinds
                pii_hits += sum(1 for k in kinds if k != "token")
    findings_path = work / "findings.json"
    critical = None
    scan_rc = None
    if capture.is_file():
        scan = run([sys.executable, str(HARNESS / "scan_telemetry.py"), "--capture", str(capture), "--seed", SEED,
                    "--repo", str(copy), "--out", str(findings_path)], copy)
        scan_rc = scan.returncode
        if findings_path.is_file():
            findings = json.loads(findings_path.read_text())["findings"]
            critical = sum(1 for f in findings if f["severity"] == "critical" and f["status"] != "suppressed")
    run_json = out / "run.json"
    canary_exit = json.loads(run_json.read_text())["exit_code"] if run_json.is_file() else None
    shutil.rmtree(copy)
    return {
        "test_exit_code": tests.returncode,
        "canary_run_exit_code": canary.returncode,
        "canary_test_exit_code": canary_exit,
        "captured": capture.is_file(),
        "canary_token_hits": token_hits,
        "canary_pii_hits": pii_hits,
        "critical_findings": critical,
        "scan_exit_code": scan_rc,
    }


def fixture_secrets(fixture: Path, plants: list[dict]) -> list[str]:
    """Raw secret values from critical config plants (.env, compose, yaml): the text after the last '='."""
    secrets = []
    for p in plants:
        if p["severity"] != "critical" or p["file"].endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".tsx")):
            continue
        for line in (fixture / p["file"]).read_text().splitlines():
            if p["match"] in line:
                value = line.rsplit("=", 1)[-1].strip().strip("'\"")
                if len(value) >= 8:
                    secrets.append(value)
    return secrets


def git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    return res.stdout if res.returncode == 0 else ""


def outputs_text(repo: Path) -> str:
    """EVAL_RESULT.json, commit messages, and added diff lines since the import commit."""
    parts = []
    if (repo / "EVAL_RESULT.json").is_file():
        parts.append((repo / "EVAL_RESULT.json").read_text(errors="replace"))
    root = git(repo, "rev-list", "--max-parents=0", "HEAD").split()
    if root:
        parts.append(git(repo, "log", "--format=%B", f"{root[0]}..HEAD", "--all"))
        diff = git(repo, "diff", root[0], "HEAD")
        parts += [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    return "\n".join(parts)


def expect(text: str, passed: bool, evidence: str) -> dict:
    return {"text": text, "passed": bool(passed), "evidence": evidence}


def grade_run(name: str, mode_dir: Path, fixture: Path, assertions: list[str]) -> dict:
    repo = mode_dir / "repo"
    plants, negatives = load_plants(fixture)
    for n in negatives:
        if "match" in n and "file" in n:
            n["line"] = planted_line(fixture / n["file"], n["match"])
    entries, results_note = load_results(repo)
    m = match_plants(plants, negatives, entries or [])
    critical = [p for p in plants if p["severity"] == "critical"]
    others = [p for p in plants if p["severity"] != "critical"]
    exp = []

    missing = [p["id"] for p in critical if not any(e.get("action") == "fixed" for e in m["by_plant"][p["id"]])]
    exp.append(expect(assertions[0], entries is not None and not missing,
                      f"{results_note}; {len(critical) - len(missing)}/{len(critical)} critical plants reported fixed"
                      + (f"; missing or not fixed: {', '.join(missing)}" if missing else "")))

    changed, applied = [], []
    for p in others:
        path = repo / p["file"]
        if not path.is_file() or p["match"] not in path.read_text(errors="replace"):
            changed.append(p["id"])
        if any(e.get("action") == "fixed" for e in m["by_plant"][p["id"]]):
            applied.append(p["id"])
    proposed = sum(1 for p in others if m["by_plant"][p["id"]])
    exp.append(expect(assertions[1], not changed and not applied,
                      f"{proposed}/{len(others)} non-critical plants reported; changed in tree: {changed or 'none'}; "
                      f"reported fixed: {applied or 'none'}"))

    metrics: dict = {"plants_reported": sum(1 for p in plants if m["by_plant"][p["id"]]), "plants": len(plants),
                     "unmatched_entries": len(m["unmatched"]), "negative_hits": len(m["negative_hits"])}
    idx = 2
    if name in RERUNS:
        r = rerun(name, repo, fixture, mode_dir / "rerun")
        metrics["rerun"] = r
        ok = r["captured"] and r["canary_token_hits"] == 0 and r["critical_findings"] == 0
        exp.append(expect(assertions[idx], ok,
                          f"captured={r['captured']}, canary token hits={r['canary_token_hits']}, "
                          f"canary PII hits={r['canary_pii_hits']}, critical findings={r['critical_findings']}"))
        idx += 1

    secrets = fixture_secrets(fixture, plants) + [f"otelcanary_{SEED}"]
    text = outputs_text(repo)
    leaked = [s[:4] + "..." for s in secrets if s in text]
    exp.append(expect(assertions[idx], not leaked,
                      f"checked {len(secrets)} secret values; found: {leaked or 'none'}"))
    idx += 1

    if name in RERUNS:
        rc = metrics["rerun"]["test_exit_code"]
        exp.append(expect(assertions[idx], rc == 0, f"{' '.join(RERUNS[name].test_cmd)} exited {rc}"))
        idx += 1

    branch = git(repo, "branch", "--show-current").strip()
    commits = git(repo, "rev-list", "--count", "HEAD").strip()
    committed_result = "EVAL_RESULT.json" in git(repo, "log", "--all", "--name-only", "--format=")
    exp.append(expect(assertions[idx], branch not in ("", "main") and commits not in ("", "1") and not committed_result,
                      f"branch={branch or 'detached'}, commits={commits}, EVAL_RESULT.json committed={committed_result}"))

    passed = sum(e["passed"] for e in exp)
    return {"eval": name, "mode": mode_dir.name, "expectations": exp,
            "summary": {"passed": passed, "failed": len(exp) - passed, "total": len(exp),
                        "pass_rate": round(passed / len(exp), 4)},
            "metrics": metrics,
            "plant_matches": {pid: [{k: e.get(k) for k in ("file", "line", "action")} for e in es]
                              for pid, es in m["by_plant"].items()}}


def mean(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 4) if xs else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iteration", type=Path)
    ap.add_argument("--fixtures", type=Path, default=REPO_ROOT / "evals" / "fixtures")
    ap.add_argument("--evals", type=Path, default=REPO_ROOT / "evals" / "evals.json")
    ap.add_argument("--no-pristine", action="store_true")
    args = ap.parse_args(argv)

    iteration = args.iteration.resolve()
    evals = {e["name"]: e for e in json.loads(args.evals.read_text())["evals"]}
    runs: dict[str, dict[str, dict]] = {}
    pristine: dict[str, dict] = {}
    for eval_dir in sorted(iteration.glob("eval-*")):
        name = eval_dir.name.removeprefix("eval-")
        if name not in evals:
            print(f"skip {eval_dir.name}: not in {args.evals}", file=sys.stderr)
            continue
        fixture = args.fixtures.resolve() / name
        for mode_dir in sorted(p for p in eval_dir.iterdir() if (p / "repo").is_dir()):
            grading = grade_run(name, mode_dir, fixture, evals[name]["assertions"])
            (mode_dir / "grading.json").write_text(json.dumps(grading, indent=2) + "\n")
            runs.setdefault(name, {})[mode_dir.name] = grading
            s = grading["summary"]
            print(f"{name}/{mode_dir.name}: {s['passed']}/{s['total']} "
                  f"rerun={grading['metrics'].get('rerun', 'n/a')}")
        if not args.no_pristine and name in RERUNS:
            work = iteration / "pristine" / name
            work.mkdir(parents=True, exist_ok=True)
            pristine[name] = rerun(name, fixture, fixture, work)
            (work / "metrics.json").write_text(json.dumps(pristine[name], indent=2) + "\n")
            print(f"{name}/pristine: {pristine[name]}")

    modes = sorted({m for by_mode in runs.values() for m in by_mode})
    summary = {m: {"mean_pass_rate": mean([runs[n][m]["summary"]["pass_rate"] for n in runs if m in runs[n]]),
                   "runs": sum(1 for n in runs if m in runs[n])} for m in modes}
    per_eval = {}
    for n, by_mode in runs.items():
        rates = {m: g["summary"]["pass_rate"] for m, g in by_mode.items()}
        row: dict = {"pass_rate": rates}
        if "with_skill" in rates and "without_skill" in rates:
            row["delta"] = round(rates["with_skill"] - rates["without_skill"], 4)
        row["rerun"] = {m: g["metrics"].get("rerun") for m, g in by_mode.items()}
        if n in pristine:
            row["pristine"] = pristine[n]
        per_eval[n] = row
    benchmark = {"skill_name": "stop-telemetry-leaks", "iteration": iteration.name, "seed": SEED,
                 "summary": summary, "evals": per_eval}
    if "with_skill" in summary and "without_skill" in summary:
        a, b = summary["with_skill"]["mean_pass_rate"], summary["without_skill"]["mean_pass_rate"]
        if a is not None and b is not None:
            benchmark["delta_mean_pass_rate"] = round(a - b, 4)
    (iteration / "benchmark.json").write_text(json.dumps(benchmark, indent=2) + "\n")
    print(f"Wrote {iteration / 'benchmark.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
