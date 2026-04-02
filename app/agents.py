import json
import os

from dotenv import load_dotenv
from google import genai

from prompts import SYSTEM_PROMPT
from mitre import fallback_mitre_mapping

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def normalize_log(log: dict) -> dict:
    return {
        "id": log.get("id"),
        "timestamp": log.get("timestamp"),
        "host": log.get("host"),
        "source": log.get("source"),
        "event_type": log.get("event_type"),
        "message": log.get("message"),
        "raw_log": log.get("raw_log", {})
    }


def local_fallback_analysis(log: dict) -> dict:
    message = log.get("message", "").lower()
    raw_log = log.get("raw_log", {})

    if "failed login" in message or raw_log.get("event_id") == 4625:
        return {
            "attack_type": "Brute Force Login Attempt",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "severity": "High",
            "confidence": "High",
            "explanation": "Multiple failed authentication attempts suggest a likely brute-force attack against an account.",
            "recommended_actions": [
                "Block or rate-limit the source IP",
                "Review account lockout settings",
                "Investigate whether any login attempts eventually succeeded"
            ],
            "escalation_needed": True
        }

    if "powershell" in message and "encoded" in message:
        return {
            "attack_type": "Suspicious PowerShell Execution",
            "mitre_technique_id": "T1059.001",
            "mitre_technique_name": "PowerShell",
            "severity": "High",
            "confidence": "High",
            "explanation": "Encoded PowerShell commands are commonly used to hide malicious execution activity.",
            "recommended_actions": [
                "Inspect the full command line and parent process",
                "Isolate the affected host if malicious behavior is confirmed",
                "Review related PowerShell and Sysmon events"
            ],
            "escalation_needed": True
        }

    if "outbound connection" in message:
        return {
            "attack_type": "Suspicious Outbound Network Activity",
            "mitre_technique_id": "T1071",
            "mitre_technique_name": "Application Layer Protocol",
            "severity": "Medium",
            "confidence": "Medium",
            "explanation": "An unusual outbound connection after script execution may indicate command-and-control or payload retrieval activity.",
            "recommended_actions": [
                "Investigate the destination IP reputation",
                "Review host process ancestry and timeline",
                "Check for additional network connections from the same host"
            ],
            "escalation_needed": True
        }

    if "credential dumping" in message or raw_log.get("target_process") == "lsass.exe":
        return {
            "attack_type": "Credential Dumping",
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "LSASS Memory",
            "severity": "Critical",
            "confidence": "High",
            "explanation": "Access to LSASS or use of tools like procdump against LSASS strongly suggests credential dumping behavior.",
            "recommended_actions": [
                "Isolate the host immediately",
                "Collect forensic evidence from the endpoint",
                "Reset potentially exposed credentials"
            ],
            "escalation_needed": True
        }

    fallback = fallback_mitre_mapping(log.get("message", ""))
    return {
        "attack_type": "Suspicious Activity",
        "mitre_technique_id": fallback["mitre_technique_id"],
        "mitre_technique_name": fallback["mitre_technique_name"],
        "severity": "Medium",
        "confidence": "Low",
        "explanation": "The event appears suspicious but could not be confidently classified through fallback logic alone.",
        "recommended_actions": [
            "Review the event manually",
            "Correlate with surrounding host and network telemetry"
        ],
        "escalation_needed": False
    }


def analyze_with_gemini(log: dict) -> dict:
    prompt = f"""
{SYSTEM_PROMPT}

Analyze this security log and return VALID JSON ONLY.

Log:
{json.dumps(log, indent=2)}
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        text_output = response.text.strip()
        return json.loads(text_output)

    except Exception as e:
        print(f"[!] Gemini unavailable, using local fallback analysis. Reason: {e}")
        return local_fallback_analysis(log)


def enrich_with_fallbacks(log: dict, analysis: dict) -> dict:
    if analysis.get("mitre_technique_id") in [None, "", "Unknown"]:
        fallback = fallback_mitre_mapping(log.get("message", ""))
        analysis["mitre_technique_id"] = fallback["mitre_technique_id"]
        analysis["mitre_technique_name"] = fallback["mitre_technique_name"]

    return analysis


def calculate_priority_score(severity: str, confidence: str) -> int:
    severity_map = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    confidence_map = {
        "Low": 1,
        "Medium": 2,
        "High": 3
    }

    return severity_map.get(severity, 2) * confidence_map.get(confidence, 1)


def generate_incident_report(log: dict) -> dict:
    normalized = normalize_log(log)
    analysis = analyze_with_gemini(normalized)
    analysis = enrich_with_fallbacks(normalized, analysis)

    report = {
        "log_id": normalized["id"],
        "timestamp": normalized["timestamp"],
        "host": normalized["host"],
        "source": normalized["source"],
        "event_type": normalized["event_type"],
        "original_message": normalized["message"],
        "attack_type": analysis.get("attack_type", "Unknown"),
        "mitre_technique_id": analysis.get("mitre_technique_id", "Unknown"),
        "mitre_technique_name": analysis.get("mitre_technique_name", "Unknown"),
        "severity": analysis.get("severity", "Medium"),
        "confidence": analysis.get("confidence", "Low"),
        "explanation": analysis.get("explanation", "No explanation provided."),
        "recommended_actions": analysis.get("recommended_actions", []),
        "escalation_needed": analysis.get("escalation_needed", False)
    }

    report["priority_score"] = calculate_priority_score(
        report["severity"],
        report["confidence"]
    )

    return report