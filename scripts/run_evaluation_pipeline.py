import asyncio
import os
from langfuse import Langfuse, Evaluation
from langfuse.api import NotFoundError, DatasetItem
from langfuse.experiment import ExperimentResult
from loguru import logger
from pydantic import BaseModel, Field
import json

from pydantic_ai.messages import ModelResponse, ToolCallPart

from app.services.agent import run_siem_assistant
from app.services.database import DATA_DIR
from app.models.assistant import AssistantResponse

def extract_tool_calls(messages) -> list[str]:
    """Extract tool names from pydantic_ai messages."""
    executed_tools = []
    for message in messages:
        if isinstance(message, ModelResponse):
            for part in message.parts:
                if isinstance(part, ToolCallPart):
                    executed_tools.append(part.tool_name)
    return executed_tools

# Initialize langfuse client (depends on environment variables LANGFUSE_SECRET_KEY, LANGFUSE_PUBLIC_KEY, LANGFUSE_HOST)
langfuse = Langfuse()

DATASET_NAME = "siem_triage_eval"

# Fallback evaluation dataset if file doesn't exist
DEFAULT_EVAL_DATA = [
    {
        "question": "Can you give me a summary of the current cases?",
        "expected_output": "total_cases",
        "metadata": {"type": "summary"}
    },
    {
        "question": "What are our top priorities?",
        "expected_output": "Priority right now:",
        "metadata": {"type": "priority"}
    },
    {
        "question": "Classify event 123e4567-e89b-12d3-a456-426614174000",
        "expected_output": "No case found",
        "metadata": {"type": "classification_not_found"}
    }
]

def read_evaluation_data():
    eval_file = DATA_DIR / "evaluation_data" / "eval_data.json"
    if eval_file.exists():
        json_string = eval_file.read_text()
        data = json.loads(json_string) 
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data
    else:
        logger.warning(f"{eval_file} not found. Using default evaluation data.")
        return DEFAULT_EVAL_DATA

def upload_evaluation_data(evaluation_data) -> bool:
    def dataset_exists(dataset_name: str) -> bool:
        try:
            langfuse.get_dataset(dataset_name)
            return True
        except Exception as e:
            if "404" in str(e) or "LangfuseNotFoundError" in str(e):
                return False
            raise e

    if not dataset_exists(DATASET_NAME):
        logger.info("Dataset does not exist.. Creating.. ")
        langfuse.create_dataset(name=DATASET_NAME)
    else:
        logger.info("Evaluation dataset already existing.")
        return True

    logger.info("Uploading evaluation data items..")
    for item in evaluation_data:
        # Support both object and dict formats
        question = item.question if hasattr(item, "question") else item["question"]
        expected_output = item.expected_output if hasattr(item, "expected_output") else item["expected_output"]
        metadata = item.metadata if hasattr(item, "metadata") else item.get("metadata", {})
        
        langfuse.create_dataset_item(
            dataset_name=DATASET_NAME,
            input={"question": question},
            expected_output=expected_output,
            metadata=metadata,
        )
    return True

# Define your task function
async def call_agent(*, item: DatasetItem, **kwargs):
    q = item.input["question"]
    # Run the assistant returning an AssistantResponse model
    run_results, messages = await run_siem_assistant(q, message_history=[])
    
    # Extract escalations for metadata
    escalations = [e.model_dump() for e in (run_results.escalation_actions_queued or [])]

    return {
        "output": run_results.message,
        "eval_metadata": {
            "top_threat": run_results.top_threat_identified,
            "escalations": escalations,
            "reasoning": run_results.reasoning,
            "tool_calls": extract_tool_calls(messages)
        },
    }

# Evaluators
def answer_relevancy(*args, **kwargs):
    run = kwargs.get("run") or kwargs.get("output") or (args[0] if len(args) > 0 else None)
    item = kwargs.get("dataset_item") or kwargs.get("item") or kwargs.get("input") or (args[1] if len(args) > 1 else None)
    
    if not item or not run:
        logger.warning(f"answer_relevancy args: {args}, kwargs: {kwargs}")
        return Evaluation(name="answer_relevancy", value=0.0, comment="Error: missing run or dataset_item")

    expected_output = item.get("expected_output", "") if hasattr(item, "get") else (item.expected_output if hasattr(item, "expected_output") else "")
    actual_output = run.get("output", "") if hasattr(run, "get") else (run.output if hasattr(run, "output") else "")
    actual_output_str = actual_output if isinstance(actual_output, str) else str(actual_output)
    
    score = 1.0 if expected_output.lower() in actual_output_str.lower() else 0.0
    return Evaluation(
        name="answer_relevancy",
        value=score,
        comment=f"Expected '{expected_output}' to be in actual output."
    )
    
def tool_calling_accuracy(*args, **kwargs):
    run = kwargs.get("run") or kwargs.get("output") or (args[0] if len(args) > 0 else None)
    if not run:
        return Evaluation(name="tool_calling_accuracy", value=0.0, comment="Error: missing run")
        
    eval_metadata = run.get("eval_metadata", {}) if hasattr(run, "get") else (run.eval_metadata if hasattr(run, "eval_metadata") else {})
    
    # Actually use tool calls now!
    tool_calls = eval_metadata.get("tool_calls", [])
    reasoning = eval_metadata.get("reasoning", [])
    
    if len(tool_calls) > 0:
        score = 1.0
        comment = f"Tools used successfully: {', '.join(tool_calls)}"
    elif reasoning:
        score = 0.5
        comment = "No tools used, but reasoning exists (likely deterministic path)."
    else:
        score = 0.0
        comment = "No tools used and no reasoning provided."
        
    return Evaluation(
        name="tool_calling_accuracy",
        value=score,
        comment=comment
    )

def create_annotation_results(eval_results: ExperimentResult):
    ## put the run into an annotation queue..
    logger.info("Skipping annotation queue creation as no valid score_config_ids are configured.")
    # In a real environment, you'd fetch or provide a valid score_config_id here:
    # queue = langfuse.api.annotation_queues.create_queue(
    #     name="queue: " + eval_results.run_name,
    #     score_config_ids=["YOUR_VALID_CONFIG_ID_HERE"],
    # )
    pass

if __name__ == "__main__":
    logger.info("Reading evaluation dataset..")
    eval_data = read_evaluation_data()

    logger.info("Uploading Langfuse dataset..")
    upload_evaluation_data(eval_data)

    logger.info("Running evaluation.. ")
    eval_dataset = langfuse.get_dataset(DATASET_NAME)
    
    evaluation_result = eval_dataset.run_experiment(
        name="SIEM Agent Evaluation",
        task=call_agent,
        evaluators=[answer_relevancy, tool_calling_accuracy],
    )

    logger.info("Creating human annotation results..")
    create_annotation_results(evaluation_result)

    logger.info("DONE")
