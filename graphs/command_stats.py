import pandas as pd

DATA_FILE = "dataset/features.csv"

def command_statistics():

    try:
        df = pd.read_csv(DATA_FILE)
    except:
        return []

    df = df.sort_values("count", ascending=False)

    return df.to_dict(orient="records")
