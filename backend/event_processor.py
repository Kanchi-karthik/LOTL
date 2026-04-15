import os
import sys
import threading
import time
import json
import hashlib
import queue
import random

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from parser.falco_parser import parse_falco_event
from detection.realtime_detector import RealtimeDetector
from backend.threat_scoring import analyze_threat
from response.incident_response import take_action
from monitoring.real_k8s_monitor import k8s_monitor
from detection.kernel_events_monitor import kernel_monitor
from backend.geolocation import geo_service

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "falco_events.log")

class EventProcessor:
    def __init__(self, mode="simulation"):
        self.detector = RealtimeDetector()
        self.mode = mode # "simulation" (file tailing) or "realtime" (k8s)
        self.state = {
            "containers_monitored": set(),
            "users_active": set(),
            "total_events": 0,
            "anomalies_detected": 0,
            "latest_events": [], # last 100 max
            "pod_stats": {},
            "user_stats": {},
            "attacker_stats": {}, # ip -> {count, location}
            "mitre_stats": {}, # technique_id -> count
            "threat_score": 0,
            "incidents": []
        }
        self.lock = threading.Lock()
        self.running = False
        self.k8s_thread = None
        self.tail_thread = None

    def start(self):
        self.running = True
        # Start each dashboard session from a clean slate so old logs do not inflate counts.
        self.clear_state()

        # Always ensure log directory exists for simulation/fallback
        if not os.path.exists(LOG_FILE):
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            if not os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'w') as f:
                    pass

        # In realtime mode, we try K8s but ALWAYS keep the log tailer as a fallback
        if self.mode == "realtime":
            k8s_monitor.start_streaming()
            self.k8s_thread = threading.Thread(target=self._process_k8s_stream, daemon=True)
            self.k8s_thread.start()
            
        # Start log tailing thread (either primary or fallback)
        self.tail_thread = threading.Thread(target=self._tail_log, daemon=True)
        self.tail_thread.start()

    def stop(self):
        self.running = False
        if self.mode == "realtime":
            k8s_monitor.running = False

    def get_state(self):
        with self.lock:
            return {
                "containers_monitored": len(self.state["containers_monitored"]),
                "users_active": len(self.state["users_active"]),
                "total_events": self.state["total_events"],
                "anomalies_detected": self.state["anomalies_detected"],
                "latest_events": list(self.state["latest_events"])[-100:], 
                "pod_stats": self.state["pod_stats"],
                "user_stats": self.state["user_stats"],
                "attacker_stats": self.state["attacker_stats"],
                "mitre_stats": self.state["mitre_stats"],
                "threat_score": self.state["threat_score"],
                "incidents": self.state["incidents"][-20:],
                "mode": self.mode
            }

    def clear_state(self):
        with self.lock:
            self.state = {
                "containers_monitored": set(),
                "users_active": set(),
                "total_events": 0,
                "anomalies_detected": 0,
                "latest_events": [],
                "pod_stats": {},
                "user_stats": {},
                "attacker_stats": {},
                "mitre_stats": {},
                "threat_score": 0,
                "incidents": []
            }

    def remove_pod(self, pod_name):
        """Manually remove a pod from monitored list and stats"""
        with self.lock:
            if pod_name in self.state["containers_monitored"]:
                self.state["containers_monitored"].remove(pod_name)
            # Find and remove from stats if name contains pod_name
            to_delete = []
            for p in self.state["pod_stats"]:
                if pod_name in p:
                    to_delete.append(p)
            for p in to_delete:
                del self.state["pod_stats"][p]

    def mark_quarantined(self, pod_name, status=True):
        """Mark a pod as quarantined in the SOC view"""
        with self.lock:
            for p in self.state["pod_stats"]:
                if pod_name in p:
                    self.state["pod_stats"][p]["quarantined"] = status

    def _process_k8s_stream(self):
        while self.running:
            try:
                # Get log line from queue
                line = k8s_monitor.log_queue.get(timeout=1.0)
                self._process_line(line)
            except queue.Empty:
                continue

    def _tail_log(self):
        # Default to live-only session tracking. Set LOTL_SKIP_HISTORY=false to replay old logs.
        skip_history = os.environ.get("LOTL_SKIP_HISTORY", "true").lower() == "true"
        with open(LOG_FILE, 'r') as f:
            if skip_history:
                # Seek to end to only process NEW events
                f.seek(0, os.SEEK_END)
                print("Skipping historical logs (LOTL_SKIP_HISTORY=true)")
            else:
                for line in f:
                    self._process_line(line)
                
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                self._process_line(line)

    def _process_line(self, line):
        event = parse_falco_event(line)
        if not event:
            return
            
        # Ensure command is a string and not empty for threat analysis
        command = event.get("command", "")
        if not command:
            # If command is missing in the structured event, try to find it in the 'output' string (fallback)
            try:
                event_data = json.loads(line)
                output = event_data.get("output", "")
                if "Command: " in output:
                    event["command"] = output.split("Command: ")[-1].strip()
            except:
                pass
        
        command = event.get("command", "")
        if not command and self.state["total_events"] % 10 != 0: # Don't process purely empty events unless rare
            return
            
        # Detect Anomaly via ML
        prediction = self.detector.predict(command)
        
        # Analyze via Kernel/Syscall Heuristics (Phase 2)
        kernel_alerts = kernel_monitor.analyze_event(event)
        process_chain_alert = kernel_monitor.track_process_chain(event)
        
        # Threat Scoring
        threat = analyze_threat(event["command"], prediction)
        
        is_anomaly = (prediction == "anomaly") or (len(kernel_alerts) > 0) or (process_chain_alert is not None) or (threat["level"] in ["High", "Critical"])
        
        # Override severity if kernel monitor flags it
        if kernel_alerts:
            threat["level"] = kernel_alerts[0]["severity"]
            threat["score"] = 95 if threat["level"] == "CRITICAL" else 80
            threat["mitre_technique"] = kernel_alerts[0]["mitre_name"]
            threat["mitre_id"] = kernel_alerts[0]["mitre_technique"]
        
        action = take_action(event.get("container", "unknown"), threat) if is_anomaly else ""
        
        # Geolocation & Attacker Tracking
        source_kind = event.get("source_kind")
        if source_kind == "simulation":
            source_ip = event.get("source_ip") or event.get("attacker_ip") or "shared-kernel-sim"
            kernel_id = event.get("kernel_id") or "shared-kernel"
            location = {
                "city": "Shared Kernel Lab",
                "country": "Local Simulation",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "LOTLGuard Simulator",
                "label": event.get("attacker_label", "Shared Kernel Simulator"),
                "kernel_id": kernel_id,
                "source_ip": source_ip,
                "pod_name": event.get("container", "shared-kernel")
            }
        else:
            if "source_ip" not in event or not event.get("source_ip"):
                # Stable IP generation based on container and user to avoid count inflation
                # We use a hash to ensure the same "unknown" source gets the same IP
                seed = f"{event.get('container','unknown')}-{event.get('user','unknown')}"
                h = hashlib.md5(seed.encode()).digest()
                source_ip = f"203.0.{h[0]}.{h[1]}"
            else:
                source_ip = event["source_ip"]

            kernel_id = event.get("kernel_id") or hashlib.md5(f"{event.get('container','unknown')}:{source_ip}".encode()).hexdigest()[:8]
            location = geo_service.get_location(source_ip)

        if isinstance(location, dict) and "label" not in location:
            location["label"] = event.get("attacker_label", "Internal Trace")
        if isinstance(location, dict):
            location["kernel_id"] = kernel_id
            location["source_ip"] = source_ip
            location["pod_name"] = event.get("container", "unknown")

        with self.lock:
            self.state["total_events"] += 1
            container = event.get("container", "unknown")
            user = event.get("user", "unknown")
            
            self.state["containers_monitored"].add(container)
            self.state["users_active"].add(user)
            
            # Track every live source so the dashboard shows one active attacker per real source IP.
            if source_ip not in self.state["attacker_stats"]:
                self.state["attacker_stats"][source_ip] = {"count": 0, "location": location}
            else:
                self.state["attacker_stats"][source_ip]["location"] = location
            self.state["attacker_stats"][source_ip]["count"] += 1

            if is_anomaly:
                self.state["anomalies_detected"] += 1
                self.state["threat_score"] = min(100, self.state["threat_score"] + threat["score"] // 4)

                # Update MITRE stats
                mitre_id = threat.get("mitre_id", "Unknown")
                self.state["mitre_stats"][mitre_id] = self.state["mitre_stats"].get(mitre_id, 0) + 1
            else:
                self.state["threat_score"] = max(0, self.state["threat_score"] - 1)
            
            enrichment = {
                **event,
                "prediction": "anomaly" if is_anomaly else "normal",
                "threat_level": threat["level"],
                "mitre_technique": threat["mitre_technique"],
                "mitre_id": threat["mitre_id"],
                "action": action,
                "attacker_ip": source_ip,
                "kernel_id": kernel_id,
                "location": location,
                "kernel_alerts": [a["description"] for a in kernel_alerts],
                "process_chain_alert": process_chain_alert["reason"] if process_chain_alert else None
            }
            
            self.state["latest_events"].append(enrichment)
            if len(self.state["latest_events"]) > 500:
                self.state["latest_events"].pop(0)
                
            if is_anomaly and (threat["level"] in ["High", "Critical"]):
                self.state["incidents"].append(enrichment)
                
            # Update Pod Stats
            if container not in self.state["pod_stats"]:
                self.state["pod_stats"][container] = {"total": 0, "anomalies": 0, "events": []}
            self.state["pod_stats"][container]["total"] += 1
            if is_anomaly:
                self.state["pod_stats"][container]["anomalies"] += 1
            self.state["pod_stats"][container]["events"].append(enrichment)
            if len(self.state["pod_stats"][container]["events"]) > 50:
                self.state["pod_stats"][container]["events"].pop(0)

            # Update User Stats
            if user not in self.state["user_stats"]:
                self.state["user_stats"][user] = {"total": 0, "anomalies": 0, "events": [], "commands_freq": {}}
            self.state["user_stats"][user]["total"] += 1
            if is_anomaly:
                self.state["user_stats"][user]["anomalies"] += 1
            self.state["user_stats"][user]["events"].append(enrichment)
            
            cmd_base = event["command"].split()[0] if event["command"] else "unknown"
            self.state["user_stats"][user]["commands_freq"][cmd_base] = self.state["user_stats"][user]["commands_freq"].get(cmd_base, 0) + 1
            
            if len(self.state["user_stats"][user]["events"]) > 50:
                self.state["user_stats"][user]["events"].pop(0)

# Default to realtime if K8s is available, else simulation
MODE = os.environ.get("LOTL_MODE", "realtime" if k8s_monitor.core_v1 else "simulation")
processor_instance = EventProcessor(mode=MODE)
