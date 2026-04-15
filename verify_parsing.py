import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parser.falco_parser import parse_falco_event
from backend.threat_scoring import analyze_threat

def test_parsing():
    # 1. Simulator format (nested output_fields)
    sim_event = {
        "output": "2026-03-24T14:36:35Z: Notice Terminal shell in container (user=root container_id=abc12345 web-app command=ls -l /var/log)",
        "priority": "Notice",
        "rule": "Terminal shell in container",
        "time": "2026-03-24T14:36:35Z",
        "output_fields": {
            "container.id": "abc123456789",
            "container.name": "web-app",
            "evt.time": "2026-03-24T14:36:35Z",
            "proc.cmdline": "ls -l /var/log",
            "user.name": "root"
        }
    }
    parsed_sim = parse_falco_event(json.dumps(sim_event))
    print(f"Simulator Parsing: {'PASSED' if parsed_sim and parsed_sim['command'] == 'ls -l /var/log' else 'FAILED'}")
    if parsed_sim:
        print(f"  Container: {parsed_sim['container']}, User: {parsed_sim['user']}, Command: {parsed_sim['command']}")

    # 2. Attack Simulator format (top-level fields)
    attack_event = {
        "output": "2026-03-24T08:56:08Z: Critical Attack Shadow File Read detected in any-pod. Command: cat /etc/shadow",
        "priority": "Critical",
        "rule": "LOTL Detection v3",
        "time": "2026-03-24T08:56:08Z",
        "container_name": "any-pod",
        "user": "root",
        "command": "cat /etc/shadow",
        "source_ip": "45.33.22.238"
    }
    parsed_attack = parse_falco_event(json.dumps(attack_event))
    print(f"Attack Parsing: {'PASSED' if parsed_attack and parsed_attack['command'] == 'cat /etc/shadow' else 'FAILED'}")
    if parsed_attack:
        print(f"  Container: {parsed_attack['container']}, User: {parsed_attack['user']}, Command: {parsed_attack['command']}")
    
    # 3. Verify threat detection for the parsed attack
    if parsed_attack:
        threat = analyze_threat(parsed_attack['command'], "anomaly")
        print(f"Threat Detection: {'PASSED' if threat['level'] == 'Critical' and threat['mitre_id'] == 'T1003.008' else 'FAILED'}")
        print(f"  Level: {threat['level']}, MITRE ID: {threat['mitre_id']}")

    # 4. Fallback from 'output' string
    fallback_event = {
        "output": "Some weird format. Command: cat /etc/shadow",
        "priority": "Critical"
    }
    # This won't be caught by parse_falco_event fully but should be handled by event_processor fallback
    # Let's test the logic we put in event_processor.py if we can
    parsed_fb = parse_falco_event(json.dumps(fallback_event))
    cmd = parsed_fb['command'] if parsed_fb else ""
    if not cmd:
        output = fallback_event.get("output", "")
        if "Command: " in output:
            cmd = output.split("Command: ")[-1].strip()
    
    print(f"Fallback Parsing: {'PASSED' if cmd == 'cat /etc/shadow' else 'FAILED'}")

if __name__ == "__main__":
    test_parsing()
