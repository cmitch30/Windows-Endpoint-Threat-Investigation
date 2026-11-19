import json
import unittest
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.types import SigmaString

BASE_DIR = Path(__file__).resolve().parent.parent
RULE_FILE = BASE_DIR / "detections" / "powershell_encoded_command.yml"
LOG_FILE = BASE_DIR / "logs" / "sysmon_events.json"


def load_rule():
    collection = SigmaCollection.load_ruleset([RULE_FILE])
    return collection.rules[0]




def matches_selection(event, selection):
    """
    Match synthetic Sysmon events against the supported
    Sigma field modifiers: endswith and contains.
    """
    for item in selection.detection_items:
        field = item.field
        event_value = str(event.get(field, "")).lower()

        if not event_value:
            return False

        modifier_names = {
            modifier.__name__
            for modifier in item.modifiers
        }

        values = [
            value.to_plain().replace("*", "").lower()
            for value in item.value
        ]

        if "SigmaEndswithModifier" in modifier_names:
            matched = any(
                event_value.endswith(value)
                for value in values
            )

        elif "SigmaContainsModifier" in modifier_names:
            matched = any(
                value in event_value
                for value in values
            )

        else:
            matched = any(
                event_value == value
                for value in values
            )

        if not matched:
            return False

    return True




def detect_encoded_powershell(event, rule):
    """Evaluate the two selections joined by AND."""
    selections = rule.detection.detections

    return (
        matches_selection(event, selections["selection_image"])
        and matches_selection(event, selections["selection_commandline"])
    )


class TestSigmaDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rule = load_rule()

        with open(LOG_FILE, "r", encoding="utf-8") as file:
            cls.events = json.load(file)

    def test_encoded_powershell_detected(self):
        event = {
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        }

        self.assertTrue(detect_encoded_powershell(event, self.rule))

    def test_normal_powershell_not_detected(self):
        event = {
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe Get-Process",
        }

        self.assertFalse(detect_encoded_powershell(event, self.rule))

    def test_unrelated_process_not_detected(self):
        event = {
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": "notepad.exe -EncodedCommand test",
        }

        self.assertFalse(detect_encoded_powershell(event, self.rule))

    def test_synthetic_sysmon_events(self):
        matches = [
            event for event in self.events
            if detect_encoded_powershell(event, self.rule)
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["EventID"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
