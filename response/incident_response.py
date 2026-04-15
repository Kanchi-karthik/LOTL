def take_action(container, threat_data):
    level = threat_data.get('level', 'Low')
    
    # Define response messages for all risk levels
    if level == 'Critical':
        msg = f"CRITICAL: Container '{container}' isolated immediately. Pod quarantined!"
    elif level == 'High':
        msg = f"HIGH: Resource '{container}' restricted. Policy violation documented."
    elif level == 'Medium':
        msg = f"MEDIUM: Baseline deviation on '{container}'. Enhanced logging active."
    else: # Low
        msg = f"LOW: Minor anomaly tracked for container '{container}'."

    # Print to terminal for visibility (captured in server logs)
    print(f"\n[INCIDENT_RESPONSE] {level.upper()} Risk -> {msg}", flush=True)
    
    return msg
