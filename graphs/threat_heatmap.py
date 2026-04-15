import pandas as pd

DATA_FILE = "dataset/features.csv"

def generate_heatmap():

    df = pd.read_csv(DATA_FILE)

    heatmap = []

    for _,row in df.iterrows():

        level = "low"

        if row["count"] > 3:
            level = "high"

        heatmap.append({

            "command":row["command"],
            "level":level

        })

    return heatmap
