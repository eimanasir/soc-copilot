from agents import generate_incident_report
from utils import load_logs, save_incidents, pretty_print_incident


def main():
    logs = load_logs("data/logs.json")
    incidents = []

    print("\nStarting SOC Copilot...\n")

    for log in logs:
        print(f"[1/4] Normalizing log {log.get('id')}...")
        print(f"[2/4] Running AI triage on log {log.get('id')}...")
        print(f"[3/4] Enriching with MITRE mapping...")
        print(f"[4/4] Generating incident report...\n")

        incident = generate_incident_report(log)
        incidents.append(incident)
        pretty_print_incident(incident)

    save_incidents("output/incidents.json", incidents)

    print("\nDone. Incident reports saved to output/incidents.json\n")


if __name__ == "__main__":
    main()