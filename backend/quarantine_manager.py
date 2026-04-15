import json
import os
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

class QuarantineManager:
    def __init__(self, data_dir="data/quarantine"):
        self.data_dir = data_dir
        self.quarantine_db = os.path.join(data_dir, "quarantine_db.json")
        self.quarantine_logs_dir = os.path.join(data_dir, "logs")
        
        # Create directories
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.quarantine_logs_dir, exist_ok=True)
        
        # Load existing DB
        self.quarantined_items = self._load_quarantine_db()
    
    def _load_quarantine_db(self) -> Dict:
        if os.path.exists(self.quarantine_db):
            try:
                with open(self.quarantine_db, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "quarantined_pods": [],
            "quarantined_users": [],
            "quarantine_history": []
        }
    
    def _save_quarantine_db(self):
        with open(self.quarantine_db, 'w') as f:
            json.dump(self.quarantined_items, f, indent=2)
    
    def log_quarantine(self, target_type: str, name: str, reason: str, threat_data: Dict, namespace: str = "default"):
        """Record a quarantine event in the persistent DB"""
        quarantine_id = hashlib.md5(f"{name}_{time.time()}".encode()).hexdigest()[:8]
        
        entry = {
            "id": quarantine_id,
            "type": target_type,
            "name": name,
            "namespace": namespace,
            "reason": reason,
            "threat_score": threat_data.get("score", 0),
            "threat_level": threat_data.get("level", "Medium"),
            "mitre_technique": threat_data.get("mitre_technique", "Unknown"),
            "mitre_id": threat_data.get("mitre_id", "-"),
            "timestamp": datetime.now().isoformat(),
            "status": "quarantined",
            "commands": threat_data.get("commands", []),
            "action_taken": f"{target_type.capitalize()} isolated and network blocked"
        }
        
        if target_type == "pod":
            self.quarantined_items["quarantined_pods"].append(entry)
        elif target_type == "user":
            self.quarantined_items["quarantined_users"].append(entry)
            
        self.quarantined_items["quarantine_history"].append(entry)
        self._save_quarantine_db()
        
        # Save detailed forensic log
        log_file = os.path.join(self.quarantine_logs_dir, f"{quarantine_id}.json")
        with open(log_file, 'w') as f:
            json.dump(entry, f, indent=2)
            
        return quarantine_id

    def search(self, query: str, search_type: str = "all") -> List[Dict]:
        results = []
        q = query.lower()
        
        # We always search history for comprehensive results
        for item in self.quarantined_items["quarantine_history"]:
            if search_type != "all" and item["type"] != search_type:
                continue
                
            match = False
            fields = ["name", "reason", "threat_level", "mitre_technique", "mitre_id"]
            for field in fields:
                if q in str(item.get(field, "")).lower():
                    item["_match_field"] = field
                    match = True
                    break
            
            if not match and "commands" in item:
                for cmd in item["commands"]:
                    if q in cmd.lower():
                        item["_match_field"] = "command"
                        match = True
                        break
            
            if match:
                results.append(item)
                
        return sorted(results, key=lambda x: x['timestamp'], reverse=True)

    def get_stats(self) -> Dict:
        history = self.quarantined_items["quarantine_history"]
        return {
            "total": len(history),
            "pods": len(self.quarantined_items["quarantined_pods"]),
            "users": len(self.quarantined_items["quarantined_users"]),
            "critical": len([i for i in history if i["threat_level"] == "Critical"]),
            "high": len([i for i in history if i["threat_level"] == "High"])
        }

    def release(self, quarantine_id: str) -> bool:
        found = False
        for item in self.quarantined_items["quarantine_history"]:
            if item["id"] == quarantine_id:
                item["status"] = "released"
                item["released_at"] = datetime.now().isoformat()
                found = True
                break
        
        if found:
            # Also update the type-specific lists
            for list_name in ["quarantined_pods", "quarantined_users"]:
                for item in self.quarantined_items[list_name]:
                    if item["id"] == quarantine_id:
                        item["status"] = "released"
                        item["released_at"] = datetime.now().isoformat()
            
            self._save_quarantine_db()
        return found

# Singleton
quarantine_manager = QuarantineManager()
