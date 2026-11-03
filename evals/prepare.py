#!/usr/bin/env python3
"""Set up one eval iteration: a fresh git repo per fixture and mode, plus the instructions for each run.

Usage: python3 evals/prepare.py [--fixtures evals/fixtures] [--out evals/workspace] [--modes with_skill,without_skill]

Creates OUT/iteration-N/eval-<fixture>/<mode>/repo (N = next free number). expected.toml is left
out; installed deps (node_modules, .venv) are symlinked to the originals and git-ignored.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_PATH = REPO_ROOT / "skills" / "stop-telemetry-leaks"
DEPS = ("node_modules", ".venv")
EXCLUDE = ("expected.toml", *DEPS, ".pytest_cache", "__pycache__", ".vitest", ".cache", "coverage", "dist")
MODES = ("with_skill", "without_skill")
GIT_ENV = {
    "GIT_AUTHOR_NAME": "eval", "GIT_AUTHOR_EMAIL": "eval@example.invalid",
    "GIT_COMMITTER_NAME": "eval", "GIT_COMMITTER_EMAIL": "eval@example.invalid",
}


def next_iteration(out: Path) -> Path:
    nums = [int(m.group(1)) for p in out.glob("iteration-*") if (m := re.fullmatch(r"iteration-(\d+)", p.name))]
    return out / f"iteration-{max(nums, default=0) + 1}"


def make_repo(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(*EXCLUDE))
    linked = [d for d in DEPS if (src / d).is_dir()]
    for d in linked:
        (dest / d).symlink_to((src / d).resolve(), target_is_directory=True)
    gitignore = dest / ".gitignore"
    existing = gitignore.read_text() if gitignore.is_file() else ""
    missing = [d for d in DEPS if d not in existing.split()]
    if missing:
        sep = "" if not existing or existing.endswith("\n") else "\n"
        gitignore.write_text(existing + sep + "".join(f"{d}\n" for d in missing))
    env = {**os.environ, **GIT_ENV}
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                ["git", "commit", "-q", "--no-verify", "--no-gpg-sign", "-m", "chore: import service"]):
        subprocess.run(cmd, cwd=dest, env=env, check=True)


def instructions(name: str, mode: str, repo: Path, prompt: str, skill: Path) -> str:
    lines = [f"## eval-{name} / {mode}", f"Working directory: {repo}"]
    if mode == "with_skill":
        lines.append(f"Skill: {skill} (read its SKILL.md first and follow it).")
    else:
        lines.append("No skill.")
    lines.append("Read nothing outside your working directory" + (" and the skill directory." if mode == "with_skill" else "."))
    lines += ["Prompt:", prompt, ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", type=Path, default=REPO_ROOT / "evals" / "fixtures")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "evals" / "workspace")
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--evals", type=Path, default=REPO_ROOT / "evals" / "evals.json")
    args = ap.parse_args(argv)

    modes = [m for m in args.modes.split(",") if m]
    if not modes or any(m not in MODES for m in modes):
        print(f"error: --modes must be a comma list of {', '.join(MODES)}", file=sys.stderr)
        return 2
    evals = json.loads(args.evals.read_text())["evals"]
    iteration = next_iteration(args.out.resolve())
    for ev in evals:
        src = args.fixtures.resolve() / ev["name"]
        if not src.is_dir():
            print(f"error: fixture not found: {src}", file=sys.stderr)
            return 2
        for mode in modes:
            make_repo(src, iteration / f"eval-{ev['name']}" / mode / "repo")
    # Agents get a copy of the skill outside this repo, so a stray search from the skill
    # directory can't reach evals/fixtures/*/expected.toml or the eval docs.
    skill = iteration / "skill" / SKILL_PATH.name
    shutil.copytree(SKILL_PATH, skill)
    print(f"Prepared {iteration}\n")
    print("Run each one in a fresh agent session with clean context:\n")
    for ev in evals:
        for mode in modes:
            repo = iteration / f"eval-{ev['name']}" / mode / "repo"
            print(instructions(ev["name"], mode, repo, ev["prompt"], skill))
    print(f"Then score: python3 {REPO_ROOT / 'evals' / 'score.py'} {iteration}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
