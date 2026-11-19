import json
from pathlib import Path
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "sysmon_events.json"


def load_events(file_path):
    """Load Sysmon events from a JSON file."""
    with open(file_path, "r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Expected a JSON list of Sysmon events.")

    return events


def analyze_events(events):
    """Identify suspicious PowerShell-related activity."""
    findings = []

    for event in events:
        event_id = event.get("EventID")
        image = event.get("Image", "").lower()
        command_line = event.get("CommandLine", "").lower()
        parent_image = event.get("ParentImage", "").lower()

        # Detect encoded PowerShell execution
        if event_id == 1 and "powershell.exe" in image:
            if (
                "-encodedcommand" in command_line
                or "-enc " in command_line
            ):
                findings.append({
                    "type": "ENCODED_POWERSHELL",
                    "severity": "HIGH",
                    "timestamp": event.get("UtcTime"),
                    "computer": event.get("Computer"),
                    "user": event.get("User"),
                    "process_guid": event.get("ProcessGuid"),
                    "command_line": event.get("CommandLine")
                })

        # Detect PowerShell network connections
        if event_id == 3 and "powershell.exe" in image:
            findings.append({
                "type": "POWERSHELL_NETWORK_CONNECTION",
                "severity": "MEDIUM",
                "timestamp": event.get("UtcTime"),
                "computer": event.get("Computer"),
                "user": event.get("User"),
                "process_guid": event.get("ProcessGuid"),
                "destination_ip": event.get("DestinationIp"),
                "destination_port": event.get("DestinationPort")
            })

        # Detect command shell spawned by PowerShell
        if event_id == 1 and "cmd.exe" in image:
            if "powershell.exe" in parent_image:
                findings.append({
                    "type": "POWERSHELL_CHILD_PROCESS",
                    "severity": "MEDIUM",
                    "timestamp": event.get("UtcTime"),
                    "computer": event.get("Computer"),
                    "user": event.get("User"),
                    "process_guid": event.get("ProcessGuid"),
                    "parent_process_guid": event.get("ParentProcessGuid"),
                    "command_line": event.get("CommandLine")
                })

    return findings


def correlate_events(events):
    """Correlate Sysmon events using process GUID relationships."""
    timeline = []

    # Identify process-creation records by their unique GUID.
    processes = {
        event["ProcessGuid"]: event
        for event in events
        if event.get("EventID") == 1
        and event.get("ProcessGuid")
    }

    for event in events:
        event_id = event.get("EventID")
        process_guid = event.get("ProcessGuid")
        parent_guid = event.get("ParentProcessGuid")

        if event_id == 1:
            parent = processes.get(parent_guid)

            timeline.append({
                "timestamp": event.get("UtcTime"),
                "event_type": "PROCESS_CREATION",
                "process": event.get("Image"),
                "process_guid": process_guid,
                "parent_process": (
                    parent.get("Image")
                    if parent
                    else event.get("ParentImage", "Unknown")
                ),
                "details": event.get("CommandLine", "")
            })

        elif event_id == 3:
            source_process = processes.get(process_guid)

            timeline.append({
                "timestamp": event.get("UtcTime"),
                "event_type": "NETWORK_CONNECTION",
                "process": (
                    source_process.get("Image")
                    if source_process
                    else event.get("Image", "Unknown")
                ),
                "process_guid": process_guid,
                "parent_process": None,
                "details": (
                    f"{event.get('DestinationIp')}:"
                    f"{event.get('DestinationPort')}"
                )
            })

    timeline.sort(key=lambda item: item["timestamp"] or "")

    return timeline


def main():
    print("=== Windows Endpoint Threat Investigation ===")

    events = load_events(LOG_FILE)

    print(f"\nTotal Sysmon events: {len(events)}")

    event_counts = Counter(event["EventID"] for event in events)

    print("\nEvent ID Summary:")
    for event_id, count in sorted(event_counts.items()):
        print(f"Event ID {event_id}: {count}")

    print("\n=== Suspicious Activity Detection ===")

    findings = analyze_events(events)

    if not findings:
        print("No suspicious activity detected.")
    else:
        for finding in findings:
            print(
                f"\n[{finding['severity']}] "
                f"{finding['type']}"
            )
            print(f"Timestamp: {finding['timestamp']}")
            print(f"Computer: {finding['computer']}")
            print(f"User: {finding['user']}")

            if "command_line" in finding:
                print(f"Command Line: {finding['command_line']}")

            if "destination_ip" in finding:
                print(
                    f"Destination: "
                    f"{finding['destination_ip']}:"
                    f"{finding['destination_port']}"
                )

            if "parent_process_guid" in finding:
                print(
                    f"Parent Process GUID: "
                    f"{finding['parent_process_guid']}"
                )

    print("\n=== Investigation Summary ===")
    print(f"Total findings: {len(findings)}")

    print("\n=== Correlated Endpoint Timeline ===")

    timeline = correlate_events(events)

    for entry in timeline:
        print(f"\nTimestamp: {entry['timestamp']}")
        print(f"Event Type: {entry['event_type']}")
        print(f"Process: {entry['process']}")

        if entry["parent_process"]:
            print(f"Parent Process: {entry['parent_process']}")

        print(f"Details: {entry['details']}")

    print(f"\nTotal correlated events: {len(timeline)}")



if __name__ == "__main__":
    main()
