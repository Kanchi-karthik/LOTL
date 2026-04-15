import os
import sys
import subprocess
import time
import shutil
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.event_processor import processor_instance
from backend.quarantine_manager import quarantine_manager
from monitoring.real_k8s_monitor import k8s_monitor
from attack_simulation.inject_command import inject as inject_simulation

app = Flask(__name__)
CORS(app)

# Start the background event processor
processor_instance.start()

# Track manually taken actions for the log
ACTIONS_TAKEN = []


def _run_kubectl(args, timeout=3):
    if not shutil.which("kubectl"):
        raise FileNotFoundError("kubectl not available")
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)

@app.route("/")
def index():
    state = processor_instance.get_state()
    return render_template("index.html", **state)

@app.route("/api/status")
def status():
    state = processor_instance.get_state()
    state["actions_taken"] = ACTIONS_TAKEN
    state["active_quarantine"] = quarantine_manager.quarantined_items.get("quarantined_pods", []) + \
                                quarantine_manager.quarantined_items.get("quarantined_users", [])
    return jsonify(state)

@app.route("/api/events")
def get_events():
    state = processor_instance.get_state()
    return jsonify(state.get("latest_events", [])[-50:])

@app.route("/api/pod/<pod_name>")
def pod_details(pod_name):
    state = processor_instance.get_state()
    stats = state.get("pod_stats", {}).get(pod_name, {"total": 0, "anomalies": 0, "events": []})
    
    # Check if pod is actually alive in Cluster
    active_pods = [p['pod'] for p in k8s_monitor.get_running_containers()]
    is_active = pod_name in active_pods
    stats["is_active"] = is_active
    
    # It's a simulation IF it's not active AND it looks like a prefix (short name)
    stats["is_simulation"] = not is_active and len(pod_name.split("-")) < 3
    
    return jsonify(stats)

@app.route("/api/user/<user_name>")
def user_details(user_name):
    state = processor_instance.get_state()
    stats = state.get("user_stats", {}).get(user_name, {"total": 0, "anomalies": 0, "events": [], "commands_freq": {}})
    return jsonify(stats)

@app.route("/api/containers")
def list_containers():
    containers = k8s_monitor.get_running_containers()
    return jsonify(containers)

# IR Action Endpoints
@app.route("/api/action/kill_process", methods=["POST"])
def kill_process():
    data = request.json
    pod_input = data.get("pod")
    cmd = data.get("command")
    
    # Improved: Print to terminal for visibility
    print(f"\n[MITIGATION] Request to KILL POD: '{pod_input}' for command: {cmd}", flush=True)

    # Fallback for empty pod input
    if not pod_input:
        pod_input = "unknown"

    try:
        if pod_input == "unknown":
            raise ValueError("Unknown pod name")

        # If kubectl is unavailable or the cluster is unreachable, fall back to SOC-only simulation.
        if not shutil.which("kubectl"):
            raise FileNotFoundError("kubectl not available")

        # 1. Try exact match first
        check = _run_kubectl(["get", "pod", pod_input], timeout=3)
        target_pod = pod_input
        
        # 2. If exact match fails, try finding a pod with that prefix
        if check.returncode != 0:
            search = _run_kubectl(["get", "pods", "-o", "jsonpath={.items[*].metadata.name}"], timeout=3)
            all_pods = search.stdout.split()
            matches = [p for p in all_pods if p.startswith(pod_input)]
            if not matches:
                raise ValueError(f"Pod '{pod_input}' not found in cluster.")
            target_pod = matches[0]

        _run_kubectl(["delete", "pod", target_pod, "--now"], timeout=5)
        processor_instance.remove_pod(target_pod) # Sync state
        msg = f"Successfully terminated pod '{target_pod}'."
        print(f"✅ [REAL-TIME] {msg}", flush=True)
        ACTIONS_TAKEN.append({"action": "Killed Pod", "target": target_pod, "reason": cmd, "time": time.ctime()})
        return jsonify({"status": "success", "message": msg})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as e:
        # Simulation Fallback (Always works for "unknown" pods)
        processor_instance.remove_pod(pod_input) # Sync state even in simulation
        msg = f"Simulated Termination: Pod '{pod_input}' removed from SOC view."
        print(f"⚠️ [SIMULATED] {msg} (Reason: {str(e)})", flush=True)
        ACTIONS_TAKEN.append({"action": "Killed Pod (Simulated)", "target": pod_input, "reason": cmd, "time": time.ctime()})
        return jsonify({"status": "success", "message": msg, "simulated": True})
    except Exception as e:
        processor_instance.remove_pod(pod_input)
        msg = f"Simulated Termination: Pod '{pod_input}' removed from SOC view."
        print(f"⚠️ [SIMULATED] {msg} (Unexpected error: {str(e)})", flush=True)
        ACTIONS_TAKEN.append({"action": "Killed Pod (Simulated)", "target": pod_input, "reason": cmd, "time": time.ctime()})
        return jsonify({"status": "success", "message": msg, "simulated": True})

@app.route("/api/action/quarantine_pod", methods=["POST"])
def quarantine_pod():
    data = request.json
    pod = data.get("pod")
    namespace = data.get("namespace", "default")
    threat_data = data.get("threat_data", {})
    
    print(f"\n[MITIGATION] Request to QUARANTINE POD: '{pod}'", flush=True)

    if not pod or pod == "unknown":
        pod = "unknown"

    success = False
    if pod != "unknown":
        success = k8s_monitor.quarantine_pod(pod, namespace)

    if success:
        quarantine_id = quarantine_manager.log_quarantine("pod", pod, "Manual Incident Response", threat_data, namespace)
        processor_instance.mark_quarantined(pod) # Sync
        print(f"✅ [REAL-TIME] Pod '{pod}' isolated. ID: {quarantine_id}", flush=True)
        ACTIONS_TAKEN.append({"action": "Quarantine Pod", "target": pod, "id": quarantine_id, "time": time.ctime()})
        return jsonify({"status": "success", "message": f"Pod '{pod}' isolated. Quarantine ID: {quarantine_id}"})
    else:
        # Simulation Fallback
        quarantine_id = quarantine_manager.log_quarantine("pod", pod, "Manual Incident Response (Simulated)", threat_data, namespace)
        processor_instance.mark_quarantined(pod) # Sync
        print(f"⚠️ [SIMULATED] Pod '{pod}' quarantined in SOC view. ID: {quarantine_id}", flush=True)
        ACTIONS_TAKEN.append({"action": "Quarantine Pod (Simulated)", "target": pod, "id": quarantine_id, "time": time.ctime()})
        return jsonify({"status": "success", "message": f"Pod '{pod}' isolated (Simulated Mode). Quarantine ID: {quarantine_id}", "simulated": True})

@app.route("/api/quarantine/search")
def quarantine_search():
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')
    results = quarantine_manager.search(query, search_type)
    return jsonify({
        "query": query,
        "type": search_type,
        "count": len(results),
        "results": results
    })

@app.route("/api/quarantine/stats")
def quarantine_stats():
    return jsonify(quarantine_manager.get_stats())

@app.route("/api/quarantine/history")
def quarantine_history():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(quarantine_manager.quarantined_items["quarantine_history"][-limit:])

@app.route("/api/quarantine/release/<quarantine_id>", methods=["POST"])
def release_action(quarantine_id):
    # Find the pod name from history
    target = None
    for item in quarantine_manager.quarantined_items["quarantine_history"]:
        if item["id"] == quarantine_id:
            target = item
            break
            
    if not target:
        return jsonify({"status": "error", "message": "Quarantine ID not found"}), 404
        
    if target["type"] == "pod":
        k8s_monitor.release_pod(target["name"], target["namespace"])
    
    quarantine_manager.release(quarantine_id)
    return jsonify({"status": "success", "message": f"Item {quarantine_id} has been released."})

@app.route("/api/action/block_user", methods=["POST"])
def block_user():
    data = request.json
    user = data.get("user")
    
    print(f"\n[MITIGATION] Request to BLOCK USER: '{user}'", flush=True)

    if not user or user == "unknown":
        user = "unknown"

    # Simulate RBAC revocation
    quarantine_id = quarantine_manager.log_quarantine("user", user, "Manual Incident Response", {})
    print(f"⚠️ [SIMULATED] RBAC roles for user '{user}' revoked. ID: {quarantine_id}", flush=True)
    ACTIONS_TAKEN.append({"action": "Block User", "target": user, "id": quarantine_id, "time": time.ctime()})
    return jsonify({"status": "success", "message": f"RBAC roles for user '{user}' have been revoked. ID: {quarantine_id}"})

@app.route("/api/action/simulate", methods=["POST"])
def simulate():
    data = request.json
    command = data.get("command")
    pod_prefix = data.get("pod", "web-app")
    
    if not command:
        return jsonify({"status": "error", "message": "No command provided."}), 400
        
    try:
        inject_simulation(command, container_prefix=pod_prefix)
        return jsonify({"status": "success", "message": f"Injected simulation for '{pod_prefix}': {command}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/actions_log")
def actions_log():
    return jsonify(ACTIONS_TAKEN)

@app.route("/api/incidents")
def get_incidents():
    state = processor_instance.get_state()
    return jsonify(state.get("incidents", []))

@app.route('/api/logs', methods=['DELETE'])
def clear_logs():
    try:
        log_file = os.path.join(os.path.dirname(__file__), "..", "logs", "falco_events.log")
        with open(log_file, 'w') as f:
            f.write("") # Truncate file
        print("\n[SOC_ACTION] Forensic logs wiped by administrator.", flush=True)
        return jsonify({"status": "success", "message": "Log file cleared."})
    except Exception as e:
        print(f"\n[SOC_ACTION] ERROR clearing logs: {str(e)}", flush=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/action/reset", methods=["POST"])
def reset_stats():
    processor_instance.clear_state()
    global ACTIONS_TAKEN
    ACTIONS_TAKEN = []
    print("\n[SOC_ACTION] Dashboard statistics and session logs reset.", flush=True)
    return jsonify({"status": "success", "message": "Dashboard statistics and action logs have been reset."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True, use_reloader=False)
