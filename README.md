SOC Copilot is a containerized AI-powered SOC triage assistant:
   -analyzes security logs
   -classifies threats
   -maps activity to MITRE ATT&CK
   -assigns severity
   -recommends response actions.

Its features include: 
   -AI-assisted alert triage
   -MITRE ATT&CK mapping
   -Severity and confidence scoring
   -Recommended response actions
   -Priority score for incident handling
   -Dockerized CLI workflow
   -JSON incident report export

The tool follows an agentic multi-step workflow:
   -Log normalization
   -AI-based threat classification
   -MITRE ATT&CK enrichment
   -Severity and confidence assignment
   -Incident report generation

The Tech Stack used includes: 
   -Python
   -Docker
   -OpenAI API
   -JSON-based security logs

Commands for local run:
```bash
python app/main.py
```

