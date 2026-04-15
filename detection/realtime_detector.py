import os
import pickle
import sys

# add parent dir
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from feature_engineering.feature_builder import FeatureBuilder

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'model')
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

class RealtimeDetector:
    def __init__(self):
        try:
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            with open(VECTORIZER_PATH, "rb") as f:
                self.vectorizer = pickle.load(f)
            self.fb = FeatureBuilder(vectorizer=self.vectorizer)
        except Exception as e:
            print(f"Error loading models. Have you trained them? Run python -m model.train_model. Error: {e}")
            sys.exit(1)
            
    def predict(self, command):
        """
        Predicts if a command is anomalous.
        Returns 'anomaly' or 'normal'.
        """
        if not command:
            return "normal"
            
        X = self.fb.transform([command])
        # IF returns 1 for inliers, -1 for outliers
        prediction = self.model.predict(X)[0]
        
        return "anomaly" if prediction == -1 else "normal"
