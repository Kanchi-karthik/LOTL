import json
import os
import sys
import subprocess
import hashlib
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "falco_events.log")

def get_real_pod_name(prefix):
    # Only try K8s if explicitly asked OR if it's lightning fast
    # Decreased timeout and added a check to skip if it hangs
    try:
        res = subprocess.run(["kubectl", "get", "pods", "-o", "jsonpath={.items[*].metadata.name}"], 
                             capture_output=True, text=True, timeout=0.5)
        if res.returncode == 0:
            pods = res.stdout.split()
            for p in pods:
                if p.startswith(prefix):
                    return p
    except Exception:
        pass
    return prefix

def inject(command, rule="Manual Injection", priority="Notice", container_prefix="manual-pod", source_ip=None, source_kind="simulation", attacker_label="Shared Kernel Simulator"):
    if not os.path.exists(os.path.dirname(LOG_FILE)):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        
    now = datetime.utcnow().isoformat() + "Z"
    
    # Resolve the full pod name if possible
    container = get_real_pod_name(container_prefix)
    
    event = {
        "output": f"{now}: {priority} {rule} (user=root container={container} command={command})",
        "priority": priority,
        "rule": rule,
        "time": now,
        "output_fields": {
            "container.name": container,
            "user.name": "root",
            "proc.cmdline": command,
            "evt.time": now
        }
    }
    
    if source_ip:
        event["source_ip"] = source_ip
        event["attacker_ip"] = source_ip
        event["kernel_id"] = hashlib.md5(f"{container}:{source_ip}".encode()).hexdigest()[:8]
    else:
        event["kernel_id"] = hashlib.md5(container.encode()).hexdigest()[:8]

    if source_kind:
        event["source_kind"] = source_kind
    if attacker_label:
        event["attacker_label"] = attacker_label
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    print(f"✅ Injected command for pod '{container}': '{command}'")
    print(f"Check your dashboard for the results!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 inject_command.py '<command_string>' [priority] [container_prefix]")
        sys.exit(1)
        
    cmd = sys.argv[1]
    pri = sys.argv[2] if len(sys.argv) > 2 else "Critical"
    prefix = sys.argv[3] if len(sys.argv) > 3 else "web-app"
    inject(cmd, priority=pri, container_prefix=prefix)
