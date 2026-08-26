import pandas as pd
from sklearn.model_selection import train_test_split

DATASET = "data/network_flows.csv"

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

X = df[features]
y = df["label"]

X_train,x_test,y_train,y_test = train_test_split(X,y,test_size = 0.3,random_state = 42)

print("Dataset: ",len(df))
print("Training Samples: ",len(X_train))
print("Testing Samples: ",len(x_test))

print("\n Training Labels:")
print(y_train.value_counts())

print("\n Testing Labels: ")
print(y_test.value_counts())