import os
from flask import Flask, request, jsonify
import joblib
import pandas as pd

from feature_extractor import extract_features
from whois_info import get_whois_info

app = Flask(__name__)

# This finds the exact directory where app.py lives (~/phishing_detector/api)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# This correctly steps up one folder and into models, no matter where you run it from
MODEL_PATH = os.path.join(BASE_DIR, "../models/phishing_xgb.joblib")
model = joblib.load(MODEL_PATH)

@app.route("/predict", methods=["POST"])
def predict():
    url = request.json["url"]

    features = extract_features(url)
    features.pop("tld", None)

    X = pd.DataFrame([list(features.values())])

    pred = int(model.predict(X)[0])
    confidence = float(model.predict_proba(X)[0][pred])

    return jsonify({
        "url": url,
        "result": "phishing" if pred == 1 else "legit",
        "confidence": confidence,
        "whois": get_whois_info(url)
    })

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
