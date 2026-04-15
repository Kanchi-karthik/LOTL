def analyze_threat(command, prediction):
    # Base threat based on ML prediction
    if prediction == "anomaly":
        score = 50
        level = "Medium"
        mitre_tech = "Unknown Anomalous Activity"
        mitre_id = "T1059"
    else:
        score = 0
        level = "Low"
        mitre_tech = "None"
        mitre_id = "None"
    
    cmd_lower = command.lower() if command else ""
    
    # Advanced Heuristics mapping LOTL to MITRE
    if "cat " in cmd_lower and ("shadow" in cmd_lower or "passwd" in cmd_lower or "id_rsa" in cmd_lower):
        score = 90
        level = "Critical"
        mitre_tech = "OS Credential Dumping"
        mitre_id = "T1003.008"
    elif "curl" in cmd_lower or "wget" in cmd_lower or "nslookup" in cmd_lower:
        score = 80
        level = "High"
        mitre_tech = "Ingress Tool Transfer / C2"
        mitre_id = "T1105 / T1071"
    elif "chmod" in cmd_lower or "chown" in cmd_lower:
        score = 65
        level = "Medium"
        mitre_tech = "File Permission Modification"
        mitre_id = "T1222.002"
    elif "bash -i" in cmd_lower or "nc -e" in cmd_lower or "sh -i" in cmd_lower:
        score = 100
        level = "Critical"
        mitre_tech = "Command and Scripting Interpreter: Unix Shell"
        mitre_id = "T1059.004"
    elif "tar " in cmd_lower and (".ssh" in cmd_lower or "/etc" in cmd_lower):
        score = 75
        level = "High"
        mitre_tech = "Archive Collected Data"
        mitre_id = "T1560.001"
    elif "cron" in cmd_lower:
        score = 85
        level = "High"
        mitre_tech = "Scheduled Task/Job: Cron"
        mitre_id = "T1053.003"
    elif "tcpdump" in cmd_lower or "strace" in cmd_lower:
        score = 70
        level = "High"
        mitre_tech = "Network/Process Sniffing"
        mitre_id = "T1040"
        
    return {"score": score, "level": level, "mitre_technique": mitre_tech, "mitre_id": mitre_id}
