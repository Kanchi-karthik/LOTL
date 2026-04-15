import subprocess
import json
import pandas as pd

DATA_FILE = "dataset/features.csv"

print("Starting Falco real-time event stream...")

process = subprocess.Popen(
    ["kubectl", "logs", "-n", "falco", "-l", "app.kubernetes.io/name=falco", "-f"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

commands = {}

for line in process.stdout:

    if "cmd=" in line:

        try:

            cmd = line.split("cmd=")[1].split(" ")[0]

            commands[cmd] = commands.get(cmd, 0) + 1

            df = pd.DataFrame(
                [{"command": k, "count": v} for k, v in commands.items()]
            )

            df.to_csv(DATA_FILE, index=False)

            print("Detected:", cmd)

        except:
            pass
