import subprocess

LOG_FILE = "logs/falco_events.log"

def collect_logs():

    print("Collecting Falco logs...")

    cmd = [
        "kubectl",
        "logs",
        "-n",
        "falco",
        "-l",
        "app.kubernetes.io/name=falco",
        "--tail=200"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    with open(LOG_FILE, "w") as f:
        f.write(result.stdout)

    print("Logs stored in", LOG_FILE)

if __name__ == "__main__":
    collect_logs()
