def fallback_mitre_mapping(message: str) -> dict:
    text = message.lower()

    if "failed login" in text or "brute" in text:
        return {
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force"
        }

    if "powershell" in text and "encoded" in text:
        return {
            "mitre_technique_id": "T1059.001",
            "mitre_technique_name": "PowerShell"
        }

    if "lsass" in text or "credential dumping" in text:
        return {
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "LSASS Memory"
        }

    if "outbound connection" in text:
        return {
            "mitre_technique_id": "T1071",
            "mitre_technique_name": "Application Layer Protocol"
        }

    return {
        "mitre_technique_id": "Unknown",
        "mitre_technique_name": "Unknown"
    }