from langfuse.api import NotFoundError, DatasetItem
from langfuse.experiment import ExperimentResult, ExperimentItemResult
from loguru import logger
from app.evaluation.evaluators import answer_relevancy, tool_calling_accuracy
from app.models.evaluation import EvalSuite
from app.services.agent import retail_agent
from app.services.langfuse_client import langfuse_client as langfuse
from app.evaluation.utils import extract_tool_calls

from app.services.database import DATA_DIR

DATASET_NAME = "42_workshop_upload_test"


# To handle the top-level list
def read_evaluation_data():
    json_string = (DATA_DIR / "evaluation_data" / "eval_data.json").read_text()
    return EvalSuite.model_validate_json(json_string)


def upload_evaluation_data(evaluation_data: EvalSuite) -> bool:
    def dataset_exists(dataset_name: str) -> bool:
        try:
            langfuse.get_dataset(dataset_name)
            return True
        except NotFoundError:
            return False
        except Exception as e:
            # Fallback to catch generic exceptions in case of SDK version differences
            if "404" in str(e) or "LangfuseNotFoundError" in str(e):
                return False
            # Re-throw if it's a different error (e.g., Auth, Network)
            raise e

    if not dataset_exists(DATASET_NAME):
        logger.info("Dataset does not exist.. Creating.. ")
        langfuse.create_dataset(name=DATASET_NAME)
    else:
        logger.info("Evaluation already existing.")
        return True

    ### upload items.
    logger.info("Uplaoding evaluation data items..")

    for item in evaluation_data.items:
        _ = langfuse.create_dataset_item(
            dataset_name=DATASET_NAME,
            input={"question": item.question},
            expected_output=item.expected_output,
            metadata=item.metadata,
        )
    return True


# Define your task function
async def call_agent(*, item: DatasetItem, **kwargs):
    run_results = await retail_agent.run(item.input["question"])

    return {
        "output": run_results.output.message,
        "eval_metadata": {"tool_calls": extract_tool_calls(run_results)},
    }


def create_annotation_results(eval_results: ExperimentResult):
    ## put the run into an annotation queue..
    logger.info("Adding experiment to annotation queue..")

    ### Optional - Get all score configuation IDs
    # Fetch a paginated list of all score configs
    configs = langfuse.api.score_configs.get()

    # Loop through and print names and their corresponding IDs
    for config in configs.data:
        print(f"Name: {config.name} | ID: {config.id}")

    queue = langfuse.api.annotation_queues.create_queue(
        name="queue: " + eval_results.run_name,
        score_config_ids=["cmnvjr511000aqf06j49s7ixw"],
    )

    item: ExperimentItemResult
    for item in eval_results.item_results:
        _ = langfuse.api.annotation_queues.create_queue_item(
            queue_id=queue.id,
            object_id=langfuse.api.trace.get(trace_id=item.trace_id).observations[0].id,
            object_type="OBSERVATION",
        )


if __name__ == "__main__":
    logger.info("Reading evaluation dataset..")
    eval_data = read_evaluation_data()

    logger.info("Uploading Langfuse dataset..")
    upload_evaluation_data(eval_data)

    logger.info("Running evaluation.. ")
    eval_dataset = langfuse.get_dataset(DATASET_NAME)
    evaluation_result = eval_dataset.run_experiment(
        name="Retail Agent Evaluation",
        task=call_agent,
        evaluators=[answer_relevancy, tool_calling_accuracy],
    )

    logger.info("Creating human annotation results..")
    create_annotation_results(evaluation_result)

    logger.info("DONE")
