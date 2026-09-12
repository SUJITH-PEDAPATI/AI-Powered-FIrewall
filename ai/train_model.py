import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

DATASET = "data/network_flows.csv"
MODEL_PATH = "ai/firewall_model.pkl"

# Labels in the dataset that mean "benign / normal" (covers the 'BENGIN' typo)
BENIGN_LABELS = {"benign", "normal", "bengin", "begnin", "bgein"}

df = pd.read_csv(DATASET)
features = [
    "duration",
    "packet_count",
    "total_bytes",
    "min_packet_size",
    "max_packet_size",
    "average_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count"
]
df = df.dropna(subset=features + ["label"])

# Binarise labels: 0 = benign, 1 = attack
# This ensures model.predict() always returns an integer (0 or 1) and
# avoids the internal ValueError that occurs when sklearn tries to
# cast string labels like 'BENGIN' to int.
df["label_bin"] = df["label"].apply(
    lambda lbl: 0 if str(lbl).strip().lower() in BENIGN_LABELS else 1
)
print("Label distribution after binarisation:")
print(df["label_bin"].value_counts())

X = df[features]
y = df["label_bin"]

X_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)
y_pred = model.predict(x_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\n Classification Report:")
print(classification_report(y_test, y_pred))

print("\n Confusion Matrix")
print(confusion_matrix(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
print(f"Model Saved to : {MODEL_PATH}")