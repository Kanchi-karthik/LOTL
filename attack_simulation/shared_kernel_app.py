import os
import subprocess
import time
import sys
import json
import hashlib
from flask import Flask, render_template_string, request, jsonify

# Add current dir to path to import inject_command
sys.path.append(os.path.dirname(__file__))
try:
    from inject_command import inject
except ImportError:
    # Fallback if not found
    def inject(cmd, priority="Notice", container_prefix="manual-pod", source_ip=None, source_kind="simulation", attacker_label="Shared Kernel Simulator"): pass

app = Flask(__name__)

# Very simple terminal UI
HTML_TEMPLATE = """
<!DOCTYPE HTML>
<html>
<head>
    <title>LOTLGuard | Shared Kernel Terminal</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { background: #0F172A; color: #10B981; font-family: 'JetBrains Mono', monospace; padding: 20px; }
        .terminal { background: #020617; border: 1px solid #1E293B; border-radius: 8px; padding: 20px; max-width: 900px; margin: 0 auto; box-shadow: 0 0 30px rgba(16, 185, 129, 0.1); }
        .header { border-bottom: 1px solid #1E293B; padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; }
        .output { height: 400px; overflow-y: auto; margin-bottom: 20px; color: #94A3B8; font-size: 0.9rem; white-space: pre-wrap; }
        .input-line { display: flex; gap: 10px; align-items: center; }
        .prompt { color: #3B82F6; font-weight: bold; }
        input { background: transparent; border: none; color: white; outline: none; flex: 1; font-family: inherit; font-size: 1rem; }
        .warning { color: #EF4444; font-size: 0.75rem; margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="header">
            <span>LOTLGuard Shared Kernel App</span>
            <span style="color: #64748B;">Target: k8s-node-01</span>
        </div>
        <div class="output" id="output">Welcome to the shared kernel simulation. Any command you run here will be monitored by the LOTLGuard SOC in real-time.
        
Type a command to begin (e.g., 'whoami', 'ls /', 'cat /etc/passwd')...</div>
        <div class="input-line">
            <span class="prompt">attacker@remote:~$</span>
            <input type="text" id="cmd" autofocus placeholder="Type command here...">
        </div>
    </div>
    <div class="warning">WARNING: This is a controlled security simulation environment. All activities are logged.</div>

    <script>
        const input = document.getElementById('cmd');
        const output = document.getElementById('output');

        input.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                const cmd = input.value;
                input.value = '';
                output.innerHTML += `\\n<span class="prompt"> attacker@remote:~$</span> ${cmd}`;
                
                try {
                    const res = await fetch('/exec', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({command: cmd})
                    });
                    const data = await res.json();
                    output.innerHTML += `\\n${data.output}`;
                } catch (err) {
                    output.innerHTML += `\\nError: ${err.message}`;
                }
                output.scrollTop = output.scrollHeight;
            }
        });
    </script>
</body>
</html>
"""

QUARANTINE_DB = "data/quarantine/quarantine_db.json"

def is_user_blocked(user="root"):
    if not os.path.exists(QUARANTINE_DB):
        return False
    try:
        with open(QUARANTINE_DB, 'r') as f:
            db = json.load(f)
            # Check active quarantined users
            for q_user in db.get("quarantined_users", []):
                if q_user.get("name") == user and q_user.get("status") == "quarantined":
                    return True
    except Exception as e:
        print(f"Error checking quarantine DB: {e}")
    return False

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/exec", methods=["POST"])
def execute():
    data = request.json
    cmd = data.get("command", "")
    user = data.get("user", "root") # Default session user

    if is_user_blocked(user):
        return jsonify({
            "output": f"\n🚫 [LOTLGuard] ACCESS DENIED: User '{user}' has been GLOBALLY BLOCKED by the SOC.\nReason: Active Malicious Activity Detected.\n"
        })

    if not cmd:
        return jsonify({"output": ""})
    
    try:
        # Generate a virtual IP based on browser fingerprint (User-Agent)
        # This ensures different browsers look like different attackers
        ua = request.headers.get('User-Agent', 'unknown')
        h_ua = hashlib.md5(ua.encode()).digest()
        # Create a stable but unique "attacker" IP for this browser
        virtual_ip = f"103.24.{h_ua[0]}.{h_ua[1]}"

        # Inject into LOTLGuard SOC
        print(f"\n[SHARED_KERNEL] Executing command: {cmd} (Attacker IP: {virtual_ip})", flush=True)
        inject(
            cmd,
            priority="Medium",
            container_prefix="shared-kernel",
            source_ip=virtual_ip,
            source_kind="simulation",
            attacker_label="Shared Kernel Simulator"
        )
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        if not output:
            output = "[Command executed with no output]"
        return jsonify({"output": output})
    except Exception as e:
        return jsonify({"output": f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5051)
