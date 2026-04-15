import time
import json
import random
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "falco_events.log")

NORMAL_COMMANDS = [
    {"cmd": "ls -l /var/log", "user": "root", "container": "web-app", "rule": "Terminal shell in container", "priority": "Notice"},
    {"cmd": "top -b -n 1", "user": "appuser", "container": "payment-service", "rule": "System info collection", "priority": "Info"},
    {"cmd": "ps aux", "user": "www-data", "container": "web-app", "rule": "Process discovery", "priority": "Info"},
    {"cmd": "grep -r error /app/logs", "user": "appuser", "container": "user-service", "rule": "Search log files", "priority": "Info"},
    {"cmd": "whoami", "user": "appuser", "container": "user-service", "rule": "System info collection", "priority": "Notice"},
    {"cmd": "date", "user": "root", "container": "kube-system", "rule": "None", "priority": "Debug"},
    {"cmd": "netstat -tuln", "user": "root", "container": "web-app", "rule": "Network reconnaissance", "priority": "Notice"},
]

def generate_event():
    now = datetime.utcnow().isoformat() + "Z"
    cmd_info = random.choice(NORMAL_COMMANDS)
    
    event = {
        "output": f"{now}: {cmd_info['priority']} {cmd_info['rule']} (user={cmd_info['user']} container_id=abc12345 {cmd_info['container']} command={cmd_info['cmd']})",
        "priority": cmd_info['priority'],
        "rule": cmd_info['rule'],
        "time": now,
        "output_fields": {
            "container.id": "abc123456789",
            "container.name": cmd_info['container'],
            "evt.time": now,
            "proc.cmdline": cmd_info['cmd'],
            "user.name": cmd_info['user']
        }
    }
    return event

def main():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    print(f"Starting Falco event stream simulator. Writing normal events to {LOG_FILE}")
    try:
        with open(LOG_FILE, 'a') as f:
            while True:
                evt = generate_event()
                f.write(json.dumps(evt) + "\n")
                f.flush()
                # sleep between 1 to 4 seconds to simulate ambient traffic
                time.sleep(random.uniform(1, 4))
    except KeyboardInterrupt:
        print("\nStopping Simulator.")

if __name__ == "__main__":
    main()
