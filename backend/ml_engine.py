import joblib
import pandas as pd

model = joblib.load("model/isolation_model.pkl")

def detect_anomalies():

    df = pd.read_csv("dataset/features.csv")

    X = df[["count"]]

    preds = model.predict(X)

    df["prediction"] = preds

    return df
