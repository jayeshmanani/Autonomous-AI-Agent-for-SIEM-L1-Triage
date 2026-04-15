import asyncio
from langfuse import Langfuse
langfuse = Langfuse()
ds = langfuse.get_dataset("siem_triage_eval")
def answer_relevancy(**kwargs):
    print("KWARGS ARE:", kwargs.keys())
    return {"name": "answer_relevancy", "score": 1, "comment": "foo"}

res = ds.run_experiment(
    name="test",
    task=lambda item: {"output": "ok"},
    evaluators=[answer_relevancy]
)
