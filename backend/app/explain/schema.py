"""The narrative output schema (architecture §13): observed, inferences, recommendations apart."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Observed(_Strict):
    statement: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)


class Inference(_Strict):
    statement: str = Field(min_length=1, max_length=600)
    supporting_ids: list[str] = Field(min_length=1, max_length=20)
    knowledge_ids: list[str] = Field(default_factory=list, max_length=10)
    confidence: Literal["low", "medium", "high"]
    alternative_explanations: list[str] = Field(min_length=1, max_length=6)


class Recommendation(_Strict):
    action: str = Field(min_length=1, max_length=400)
    rationale_ids: list[str] = Field(min_length=1, max_length=20)


class NarrativeOutput(_Strict):
    summary: str = Field(min_length=1, max_length=1200)
    observed: list[Observed] = Field(max_length=20)
    inferences: list[Inference] = Field(max_length=10)
    recommendations: list[Recommendation] = Field(max_length=10)
    open_questions: list[str] = Field(max_length=10)
