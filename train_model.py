import pandas as pd
import joblib
from tqdm import tqdm
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from api.feature_extractor import extract_features

print("[*] Loading dataset...")
df = pd.read_csv("data/big_urls.csv").dropna()

X, y = [], []

print("[*] Extracting features...")

for url, label in tqdm(zip(df['url'], df['label']), total=len(df)):
    try:
        f = extract_features(url)
        f.pop("tld", None)
        X.append(list(f.values()))
        y.append(label)
    except:
        continue

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("[*] Training XGBoost model...")

model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

print(classification_report(y_test, pred))

joblib.dump(model, "models/phishing_xgb.joblib")

print("[✓] Model saved!")
