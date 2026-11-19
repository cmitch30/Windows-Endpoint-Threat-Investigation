from pathlib import Path

from sigma.collection import SigmaCollection

BASE_DIR = Path(__file__).resolve().parent.parent
RULE_FILE = BASE_DIR / "detections" / "powershell_encoded_command.yml"


def main():
    print("=== Sigma Detection Rule Validation ===")

    try:
        collection = SigmaCollection.load_ruleset([RULE_FILE])

        print(f"Validation successful: {len(collection.rules)} rule(s) loaded")

        for rule in collection.rules:
            print(f"\nRule Title: {rule.title}")
            print(f"Rule ID: {rule.id}")
            print(f"Log Source: {rule.logsource}")
            print(f"Detection Conditions: {len(rule.detection.condition)}")

    except Exception as error:
        print(f"Validation failed: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
