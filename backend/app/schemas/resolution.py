from __future__ import annotations

from typing import Annotated, Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator

Note = Annotated[str, StringConstraints(strip_whitespace=True, min_length=20, max_length=2000)]
Reference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=160)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def no_control_characters(cls, value):
        if isinstance(value, str) and any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError("control characters are not accepted")
        return value


class RecoveryPlan(StrictInput):
    baseline_sha256: Digest
    baseline_summary: Note
    ticket_reference: Reference
    rollback_plan: Note


class WorkflowCreate(RecoveryPlan):
    host_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    source_category: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    family: Annotated[str, StringConstraints(min_length=1, max_length=32)]


class RevisionInput(StrictInput):
    expected_revision: int = Field(ge=1, strict=True)


class DecisionInput(RevisionInput):
    note: Note


class CheckpointInput(DecisionInput):
    checkpoint: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    outcome: Literal["done", "not_applicable", "failed"] = "done"
    artifact_sha256: Digest
    artifact_reference: Reference
    observed_at: AwareDatetime


class VerificationInput(DecisionInput):
    artifact_sha256: Digest
    artifact_reference: Reference
    observed_at: AwareDatetime


class EscalationInput(DecisionInput):
    assigned_to: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    ticket_reference: Reference
    due_at: AwareDatetime


class RebaselineInput(RecoveryPlan, RevisionInput):
    family: Annotated[str, StringConstraints(min_length=1, max_length=32)] | None = None
