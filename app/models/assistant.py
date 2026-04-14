from pydantic import BaseModel, Field


class EscalationAction(BaseModel):
    event_id: str = Field(description="Event identifier for the escalated case.")
    action: str = Field(description="Escalation action and destination queue.")


class AssistantResponse(BaseModel):
    message: str = Field(description="Conversational response to the SOC analyst.")
    top_threat_identified: str | None = Field(
        default=None,
        description="Most important threat/event identified from the current context.",
    )
    escalation_actions_queued: list[EscalationAction] | None = Field(
        default=None,
        description="List of escalation actions queued by the assistant.",
    )
