import json
import os


def load_logs(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_incidents(path: str, incidents):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)


def pretty_print_incident(incident: dict):
    print("=" * 60)
    print(f"Log ID: {incident.get('log_id')}")
    print(f"Host: {incident.get('host')}")
    print(f"Attack Type: {incident.get('attack_type')}")
    print(f"MITRE: {incident.get('mitre_technique_id')} - {incident.get('mitre_technique_name')}")
    print(f"Severity: {incident.get('severity')}")
    print(f"Confidence: {incident.get('confidence')}")
    print(f"Priority Score: {incident.get('priority_score')}")
    print(f"Escalation Needed: {incident.get('escalation_needed')}")
    print(f"Explanation: {incident.get('explanation')}")
    print("Recommended Actions:")
    for action in incident.get("recommended_actions", []):
        print(f" - {action}")
    print("=" * 60)