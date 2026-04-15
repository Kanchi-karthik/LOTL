import json

def parse_falco_event(log_line):
    """
    Parses a JSON line from the Falco log stream into a structured dictionary.
    Supports both nested output_fields (standard Falco) and top-level fields (attack simulator).
    """
    line = log_line.strip()
    if not line:
        return None
        
    try:
        event = json.loads(line)
        output_fields = event.get("output_fields", {})
        
        # Priority mapping for different formats
        priority = event.get("priority") or event.get("severity") or "Notice"
        
        # Extract fields with fallback logic
        parsed = {
            "time": event.get("time") or output_fields.get("evt.time"),
            "priority": priority,
            "rule": event.get("rule") or "Unknown Rule",
            "container": output_fields.get("container.name") or event.get("container_name") or event.get("container") or "unknown",
            "user": output_fields.get("user.name") or event.get("user") or "unknown",
            "command": output_fields.get("proc.cmdline") or event.get("command") or event.get("proc.cmdline") or "",
            "source_ip": event.get("source_ip") or event.get("attacker_ip") or output_fields.get("fd.rip"),
            "attacker_ip": event.get("attacker_ip") or event.get("source_ip") or output_fields.get("fd.rip"),
            "kernel_id": event.get("kernel_id") or output_fields.get("kernel.id"),
            "source_kind": event.get("source_kind"),
            "attacker_label": event.get("attacker_label")
        }
        return parsed
    except Exception as e:
        # Silently ignore non-JSON or malformed log lines
        return None
