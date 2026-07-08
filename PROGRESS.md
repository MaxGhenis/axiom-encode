# Maximum-traceability part 2 — LLM judge stages

Branch `traceability-judge-stages` off `origin/main` (925b569f, release 0.2.1190).
Feature release target: **0.2.1191** (pyproject + `__init__.__version__` + uv.lock).

## Design invariants
- **Cross-family judging.** Generator is `gpt-5.5`; judges run on a Claude-family
  model (`claude-haiku-4-5-20251001` default, sonnet escalation on low confidence).
  A cross-family guard rejects any judge model matching the generator's family.
- **Fail-closed, fail-open banned.** Any judge failure (missing key, SDK missing,
  API error, parse failure, guard trip) emits a `judge_error` event with
  `verdict == "error"` — never silently a pass.
- **Advisory first.** Referees emit a `needs-review` label + run-log event, not a
  hard gate. Promotion is a later decision on the calibration evidence.
- **Pre-classifier never drops.** Every worklist entry gets a class + route;
  on uncertainty/error it is marked skip-with-reason, never dropped, never
  silently generated.
- Coordinated the judge-event shape once on #738 (comment 4913864260); built
  against the provisional `axiom_encode.judges.run_log` dataclass until the
  canonical schema lands.

## Status
- [x] Setup: worktree from origin/main; venv (.[dev,api], anthropic 0.116.0)
- [x] Secrets: ANTHROPIC_API_KEY + OPENAI_API_KEY provisioned as repo secrets
- [x] Coordination comment on #738
- [ ] run_log.py (provisional schema)  ·  client.py (cross-family client)
- [ ] Stage 1 statutory-fidelity referee + calibration harness (N>=30 replay)
- [ ] Stage 2 grid-adequacy judge + follow-up hook
- [ ] Stage 3 disposition referee (>=3 sampled-record arithmetic)
- [ ] Stage 4 worklist pre-classifier + bulk-encode.yml wiring
- [ ] Golden-regeneration drift check (weekly scheduled workflow)
- [ ] Tests incl. negative (judge_error visible; preclassify never drops)
- [ ] Version trio bump 0.2.1191 + changelog fragments
- [ ] Calibration FP/FN numbers for PR body

## Spend-limit protocol
If a spend limit is hit, stop cleanly, record remaining work here, and exit —
no partial uncommitted state.
