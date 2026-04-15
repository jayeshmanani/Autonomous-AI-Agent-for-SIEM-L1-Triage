import asyncio
import os
from langfuse import Langfuse
from langfuse.api import NotFoundError, DatasetItem
from langfuse.experiment import ExperimentResult
from loguru import logger
from pydantic import BaseModel, Field
import json

from app.services.agent import run_siem_assistant
from app.services.database import DATA_DIR
from app.models.assistant import AssistantResponse

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
    run_results, _ = await run_siem_assistant(q, message_history=[])
    
    # Extract escalations for metadata
    escalations = [e.model_dump() for e in (run_results.escalation_actions_queued or [])]

    return {
        "output": run_results.message,
        "eval_metadata": {
            "top_threat": run_results.top_threat_identified,
            "escalations": escalations,
            "reasoning": run_results.reasoning
        },
    }

# Evaluators
def answer_relevancy(run, item, **kwargs):
    expected_output = item.expected_output
    actual_output = run.output if isinstance(run.output, str) else str(run.output)
    
    score = 1.0 if expected_output.lower() in actual_output.lower() else 0.0
    return {
        "name": "answer_relevancy",
        "score": score,
        "comment": f"Expected '{expected_output}' to be in actual output."
    }
    
def tool_calling_accuracy(run, item, **kwargs):
    # Dummy evaluator for tool calling accuracy, assuming reasoning captures some tool calls
    return {
        "name": "tool_calling_accuracy",
        "score": 1.0 if run.eval_metadata.get("reasoning") else 0.5,
        "comment": "Check if reasoning is populated as a proxy for tool usage."
    }

def create_annotation_results(eval_results: ExperimentResult):
    ## put the run into an annotation queue..
    logger.info("Adding experiment to annotation queue..")
    try:
        queue = langfuse.api.annotation_queues.create_queue(
            name="queue: " + eval_results.run_name,
        )

        for item in eval_results.item_results:
            trace_id = item.trace_id
            if trace_id:
                trace = langfuse.api.trace.get(trace_id=trace_id)
                observations = trace.observations if hasattr(trace, 'observations') else []
                if observations:
                    langfuse.api.annotation_queues.create_queue_item(
                        queue_id=queue.id,
                        object_id=observations[0].id,
                        object_type="OBSERVATION",
                    )
    except Exception as e:
         logger.warning(f"Could not create annotation queue: {e}")

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
