import subprocess
import pandas as pd

DATA_FILE = "dataset/features.csv"

THRESHOLD = 3


def block_malicious_pods():

    df = pd.read_csv(DATA_FILE)

    suspicious = df[df["count"] > THRESHOLD]

    if suspicious.empty:
        print("No malicious activity detected")
        return

    pods = subprocess.getoutput("kubectl get pods -o name").splitlines()

    for pod in pods:

        pod_name = pod.replace("pod/","")

        print(f"Blocking suspicious pod: {pod_name}")

        subprocess.run(["kubectl","delete","pod",pod_name])
