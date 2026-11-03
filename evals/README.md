# Evals

How I tested whether the skill helps. None of this ships with the skill; `npx skills add` only installs `skills/stop-telemetry-leaks/`.

## How it works

I give a fresh agent one of the [fixture apps](fixtures/) and the same prompt twice: once with the skill, once without. The prompt is in `evals.json`.

Then I grade both runs two ways:

1. **Did it find and fix the planted leaks?** Its report gets matched against the app's `expected.toml`.
2. **Do secrets still leak?** This is the one I trust more. I take the agent's final code, add canary tests it never saw (`canary_tests/`), run them with fake secrets, and count how many show up in what the exporters send. The tooling for that lives in `harness/`, which also runs on the untouched app for a baseline.

## Results

From the run on 2026-11-03 (full grading in `results/`). Fake secrets still leaking after each agent finished:

| App | Untouched | Without skill | With skill |
|---|---|---|---|
| FastAPI | 24 | 9 | 2 |
| Express | 38 | 2 | 0 |
| Fastify | 20 | 12 | 0 |

On the session replay app, the agent without the skill fixed 2 of 7 critical leaks. With it, 7 of 7.

Without the skill, API keys stayed in exported URLs on the FastAPI and Fastify apps. The 2 left with the skill were a token inside an exception message, where the agent proposed the fix instead of applying it.

One run of each isn't a lot. Treat these as a sanity check, not a benchmark.

These runs used the earlier version of the skill, where the fake-secret verification ran every time. It's now optional and off by default, and these results haven't been rerun with the static-only default yet.

## Run it yourself

```sh
python3 evals/prepare.py --out /tmp/stl-eval     # copies each app, minus the answer key
# start a fresh agent per run, using the printed instructions
python3 evals/score.py /tmp/stl-eval/iteration-1
```

Install the fixture dependencies first ([fixtures/README.md](fixtures/README.md)). Keep the agents out of this repo while they work, since `expected.toml` and `canary_tests/` give the answers away.
