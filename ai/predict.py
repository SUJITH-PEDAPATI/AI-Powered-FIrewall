import joblib
import pandas as pd

MODEL_PATH = "ai/firewall_model.pkl"

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

model = joblib.load(MODEL_PATH)
def predict_flow(flow):
    data = {}
    for feature in features:
        data[feature] = flow[feature]
    X = pd.DataFrame([data])
    prediction = model.predict(X)[0]
    if hasattr(model,"predict_proba"):
        probabilites = model.predict_proba(X)[0]
        confidence = max(probabilites)
    else:
        confidence = None

    return prediction,confidence