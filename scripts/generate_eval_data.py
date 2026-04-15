import json
import random

# Read sample logs
logs = []
with open("data/sample_logs.json", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            logs.append(json.loads(line))
        except:
            pass

# Generate eval items
items = []

# Add some general summary queries
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

# Generate specific lookup and escalate queries
sampled_logs = random.sample(logs, min(80, len(logs)))
for log in sampled_logs:
    action_type = random.choice(["lookup", "escalate", "search_ip", "search_technique"])
    
    event_id = log.get("event_id")
    src_ip = log.get("src_ip")
    mitre = None
    if "additional_info" in log and "MITRE Technique:" in log["additional_info"]:
        mitre = log["additional_info"].split("MITRE Technique:")[1].strip().split()[0]
    
    if action_type == "lookup":
        items.append({
            "question": f"What is the status of event {event_id}?",
            "expected_output": event_id,
            "metadata": {"expected_tool_calls": ["lookup_case"]}
        })
    elif action_type == "escalate":
        items.append({
            "question": f"Please escalate event {event_id} to L2 due to suspicious activity.",
            "expected_output": "escalated successfully",
            "metadata": {"expected_tool_calls": ["escalate"]}
        })
    elif action_type == "search_ip" and src_ip:
        items.append({
            "question": f"Are there any incidents involving IP address {src_ip}?",
            "expected_output": src_ip,
            "metadata": {"expected_tool_calls": ["search"]}
        })
    elif action_type == "search_technique" and mitre:
        items.append({
            "question": f"Search for recent cases involving {mitre}.",
            "expected_output": mitre,
            "metadata": {"expected_tool_calls": ["search"]}
        })

# Pad the remaining to reach roughly 100, if not already.
additional_questions = [
    "What are our top priorities?",
    "Show me the summary of escalated cases",
    "Which cases are marked as emergency?"
] * 10

for q in additional_questions[:100 - len(items)]:
    items.append({
        "question": q,
        "expected_output": "",
        "metadata": {"expected_tool_calls": ["fetch_triage_summary", "fetch_triage_data"]}
    })

# Write to eval_data.json
final_data = {"items": items}
with open("data/evaluation_data/eval_data.json", "w", encoding="utf-8") as f:
    json.dump(final_data, f, indent=2)

print(f"Generated {len(items)} eval items.")
