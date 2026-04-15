import pandas as pd
import time

LOG_FILE = "logs/attack_timeline.csv"

def record_event(command):

    timestamp = int(time.time())

    try:
        df = pd.read_csv(LOG_FILE)
    except:
        df = pd.DataFrame(columns=["timestamp","command"])

    df.loc[len(df)] = [timestamp, command]

    df.to_csv(LOG_FILE, index=False)
