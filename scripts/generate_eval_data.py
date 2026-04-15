import json
import random

# Read actual core DB cases
try:
    with open("data/initial_triage_cases.json", "r", encoding="utf-8") as f:
        cases = json.load(f)
except Exception as e:
    print(f"Failed to load DB cases: {e}")
    cases = []

items = []

# Global scope questions
items.append({
    "question": "Can you provide a summary of the current triage cases?",
    "expected_output": "Current case overview",
    "metadata": {"expected_tool_calls": ["fetch_triage_summary"]}
})
items.append({
    "question": "What cases should I prioritize right now?",
    "expected_output": "Priority right now",
    "metadata": {"expected_tool_calls": ["fetch_triage_data"]}
})
items.append({
    "question": "Give me a list of all escalated cases.",
    "expected_output": "escalated",
    "metadata": {"expected_tool_calls": ["fetch_triage_data"]}
})

# Generate specific questions from the actual database cases
sampled_cases = random.sample(cases, min(90, len(cases)))

for case in sampled_cases:
    tools_pool = ["lookup_case", "escalate", "classify_and_tag", "search_type", "search_class", "search_str"]
    action_type = random.choice(tools_pool)
    
    event_id = case.get("event_id", "")
    event_type = case.get("event_type", "")
    classification = case.get("classification", "")
    additional_info = case.get("additional_info", "")
    
    if action_type == "lookup_case":
        items.append({
            "question": f"What is the current status and details of event {event_id}?",
            "expected_output": event_id,
            "metadata": {"expected_tool_calls": ["lookup_case"]}
        })
    elif action_type == "escalate":
        items.append({
            "question": f"Review event {event_id} and please escalate it immediately.",
            "expected_output": "escalated successfully",
            "metadata": {"expected_tool_calls": ["escalate"]}
        })
    elif action_type == "classify_and_tag":
        items.append({
            "question": f"Classify case {event_id} as false_positive and tag it with 'ignore'.",
            "expected_output": "classified successfully",
            "metadata": {"expected_tool_calls": ["classify_and_tag"]}
        })
    elif action_type == "search_type" and event_type:
        items.append({
            "question": f"Find all cases related to the event type: {event_type}.",
            "expected_output": event_type,
            "metadata": {"expected_tool_calls": ["search"]}
        })
    elif action_type == "search_class" and classification:
        items.append({
            "question": f"Are there any incidents flagged with the classification '{classification}'?",
            "expected_output": classification,
            "metadata": {"expected_tool_calls": ["search"]}
        })
    elif action_type == "search_str" and additional_info and "MITRE Technique:" in additional_info:
        mitre = additional_info.split("MITRE Technique:")[1].strip().split()[0]
        items.append({
            "question": f"Search for any recent cases involving technique {mitre}.",
            "expected_output": mitre,
            "metadata": {"expected_tool_calls": ["search"]}
        })

# Pad out remaining
for q in ["What are our top emergency priorities?", "Summary of all new events", "Which case has the highest risk score"]:
    items.append({
        "question": q,
        "expected_output": "",
        "metadata": {"expected_tool_calls": ["fetch_triage_summary", "fetch_triage_data"]}
    })

# Write out the JSON for eval
final_data = {"items": items}
with open("data/evaluation_data/eval_data.json", "w", encoding="utf-8") as f:
    json.dump(final_data, f, indent=2)

print(f"Generated {len(items)} items grounded in initial_triage_cases.json.")
