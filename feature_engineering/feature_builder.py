import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

class FeatureBuilder:
    def __init__(self, vectorizer=None):
        self.vectorizer = vectorizer or TfidfVectorizer(max_features=20)
        
    def fit(self, commands):
        self.vectorizer.fit(commands)
    
    def transform(self, commands):
        # Extracts TF-IDF features + length/args count
        X_tfidf = self.vectorizer.transform(commands).toarray()
        
        X_custom = []
        for cmd in commands:
            cmd = str(cmd)
            length = len(cmd)
            num_args = len(cmd.split()) - 1
            has_path = 1 if '/' in cmd else 0
            has_network = 1 if 'http' in cmd or 'tcp' in cmd or 'wget' in cmd or 'curl' in cmd else 0
            has_redirect = 1 if '>' in cmd or '<' in cmd else 0
            
            X_custom.append([length, num_args, has_path, has_network, has_redirect])
            
        # Combine tf-idf features and custom features
        X_combined = np.hstack((X_tfidf, np.array(X_custom)))
        return X_combined
