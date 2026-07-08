"""Provisional judge-event dataclasses for the ``axiom_encode.run_log.v1`` schema.

Part 2 of the maximum-traceability program (the LLM judge stages). A parallel
worker is speccing the canonical run-artifact schema
(TheAxiomFoundation/axiom-encode#738, "Define the run artifact schema"). Until
that lands, the judge stages emit against these provisional dataclasses, which
produce exactly the ``judge`` event shape proposed on #738. When the canonical
schema publishes, re-point :data:`SCHEMA_VERSION` and align field names in one
pass.

Design invariants encoded here:

* Every event carries ``schema`` and ``event_type == "judge"`` so a run-log
  consumer can dispatch without guessing.
* ``verdict == "error"`` is the fail-closed state: the judge could not reach a
  verdict (API failure, parse failure, cross-family guard). It is NEVER treated
  as a pass. :func:`error_event` is the only sanctioned way to build one, and it
  always sets ``judge_error``.
* ``verdict == "skip"`` is reserved for the pre-classifier's route-to-skip-with-
  reason path; it is not a pass either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

# Bump/re-point this single constant when the canonical run-artifact schema
# lands from #738. Every emitted event stamps it.
SCHEMA_VERSION = "axiom_encode.run_log.v1"

EVENT_TYPE = "judge"


class JudgeStage(str, Enum):
    """The judge stage that produced an event."""

    STATUTORY_FIDELITY = "statutory_fidelity"
    GRID_ADEQUACY = "grid_adequacy"
    DISPOSITION = "disposition"
    WORKLIST_PRECLASSIFY = "worklist_preclassify"
    GOLDEN_DRIFT = "golden_drift"


class Verdict(str, Enum):
    """Structured verdict.

    ``ERROR`` is the fail-closed state (never a pass). ``SKIP`` is the
    pre-classifier's route-to-skip-with-reason path (also not a pass).
    """

    PASS = "pass"
    FLAG = "flag"
    ERROR = "error"
    SKIP = "skip"


# Extensible finding taxonomy. Kept as a frozenset so tests and the run-log
# consumer can validate ``kind`` without importing every stage module.
FINDING_KINDS = frozenset(
    {
        "unrepresented_clause",
        "untraceable_branch",
        "boundary_direction",
        "amount_mismatch",
        "untested_region",
        "claim_mismatch",
        "routing",
        "drift",
        "insufficient_records",
        "judge_error",
    }
)


def coerce_confidence(value: Any) -> Optional[float]:
    """Safely coerce a model-supplied confidence to a clamped [0,1] float.

    Returns ``None`` for a missing or non-numeric value rather than raising — a
    model that answers ``"high"`` must not crash a stage (and, in the
    pre-classifier's batch path, take every other entry down with it). Values are
    clamped to [0,1] so an emitted event always satisfies ``validate_event_dict``.
    """

    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f < 0.0:
        f = 0.0
    elif f > 1.0:
        f = 1.0
    return round(f, 4)


def _round_conf(value: Optional[float]) -> Optional[float]:
    return coerce_confidence(value)


@dataclass(frozen=True)
class Finding:
    """A single machine-checkable finding.

    ``clause_ref`` locates the provision; ``rule_path`` locates the generated
    artifact locus; ``kind`` is drawn from :data:`FINDING_KINDS`.
    """

    clause_ref: str
    rule_path: str
    kind: str
    explanation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "clause_ref": self.clause_ref,
            "rule_path": self.rule_path,
            "kind": self.kind,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class TokenCounts:
    """Judge token spend, logged into the event for cost control."""

    input: int = 0
    output: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"input": int(self.input), "output": int(self.output)}

    def __add__(self, other: "TokenCounts") -> "TokenCounts":
        return TokenCounts(self.input + other.input, self.output + other.output)


@dataclass(frozen=True)
class JudgeError:
    """Populated iff ``verdict == error``. Fail-open is banned."""

    type: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "message": self.message}


@dataclass
class JudgeEvent:
    """A single ``axiom_encode.run_log.v1`` judge event."""

    stage: JudgeStage
    verdict: Verdict
    confidence: Optional[float] = None
    advisory: bool = True
    findings: list[Finding] = field(default_factory=list)
    model: Optional[str] = None
    generator_model: Optional[str] = None
    escalated: bool = False
    tokens: TokenCounts = field(default_factory=TokenCounts)
    judge_error: Optional[JudgeError] = None
    run_id: Optional[str] = None
    subject_ref: Optional[str] = None
    # Stage-specific machine-readable payload the deterministic follow-up hooks
    # consume (grid gaps -> suggested cells, disposition arithmetic, preclassify
    # routing). Kept off ``findings`` so findings stay uniform across stages.
    extra: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def is_error(self) -> bool:
        return self.verdict == Verdict.ERROR

    @property
    def passed(self) -> bool:
        # ERROR and SKIP are explicitly NOT passes.
        return self.verdict == Verdict.PASS

    @property
    def needs_review(self) -> bool:
        """Advisory label signal: a flagged referee wants human review."""
        return self.verdict == Verdict.FLAG

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "event_type": EVENT_TYPE,
            "stage": self.stage.value,
            "verdict": self.verdict.value,
            "confidence": _round_conf(self.confidence),
            "advisory": bool(self.advisory),
            "findings": [f.to_dict() for f in self.findings],
            "model": self.model,
            "generator_model": self.generator_model,
            "escalated": bool(self.escalated),
            "tokens": self.tokens.to_dict(),
            "judge_error": self.judge_error.to_dict() if self.judge_error else None,
            "run_id": self.run_id,
            "subject_ref": self.subject_ref,
            "extra": self.extra,
            "created_at": self.created_at,
        }


def error_event(
    stage: JudgeStage,
    message: str,
    *,
    error_type: str = "judge_error",
    model: Optional[str] = None,
    generator_model: Optional[str] = None,
    tokens: Optional[TokenCounts] = None,
    escalated: bool = False,
    run_id: Optional[str] = None,
    subject_ref: Optional[str] = None,
) -> JudgeEvent:
    """Build a fail-closed ``judge_error`` event.

    This is the ONLY sanctioned construction of an error verdict. A judge that
    cannot reach a verdict must return this — never a pass. The error is also
    surfaced as a ``judge_error`` finding so a consumer scanning ``findings``
    still sees it.
    """

    return JudgeEvent(
        stage=stage,
        verdict=Verdict.ERROR,
        confidence=None,
        advisory=True,
        findings=[
            Finding(
                clause_ref=subject_ref or "",
                rule_path=subject_ref or "",
                kind="judge_error",
                explanation=message,
            )
        ],
        model=model,
        generator_model=generator_model,
        escalated=escalated,
        tokens=tokens or TokenCounts(),
        judge_error=JudgeError(type=error_type, message=message),
        run_id=run_id,
        subject_ref=subject_ref,
    )


def validate_event_dict(payload: dict[str, Any]) -> list[str]:
    """Return a list of schema problems (empty == valid).

    Used by tests and by any run-log consumer that wants to reject malformed
    judge events. Enforces the load-bearing invariant: ``error`` verdict implies
    a non-null ``judge_error`` and vice versa (fail-open cannot masquerade as a
    pass).
    """

    problems: list[str] = []
    if payload.get("schema") != SCHEMA_VERSION:
        problems.append(f"schema must be {SCHEMA_VERSION!r}")
    if payload.get("event_type") != EVENT_TYPE:
        problems.append(f"event_type must be {EVENT_TYPE!r}")
    stage = payload.get("stage")
    if stage not in {s.value for s in JudgeStage}:
        problems.append(f"unknown stage {stage!r}")
    verdict = payload.get("verdict")
    if verdict not in {v.value for v in Verdict}:
        problems.append(f"unknown verdict {verdict!r}")
    err = payload.get("judge_error")
    if verdict == Verdict.ERROR.value and not err:
        problems.append("error verdict must carry judge_error (fail-open banned)")
    if verdict != Verdict.ERROR.value and err:
        problems.append("judge_error present on non-error verdict")
    conf = payload.get("confidence")
    if conf is not None and not (0.0 <= float(conf) <= 1.0):
        problems.append("confidence out of [0,1]")
    for i, finding in enumerate(payload.get("findings") or []):
        for key in ("clause_ref", "rule_path", "kind", "explanation"):
            if key not in finding:
                problems.append(f"finding[{i}] missing {key}")
        if finding.get("kind") not in FINDING_KINDS:
            problems.append(f"finding[{i}] unknown kind {finding.get('kind')!r}")
    return problems
