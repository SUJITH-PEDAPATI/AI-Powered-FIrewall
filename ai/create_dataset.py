import json
import pandas as pd
flows = []

OUTPUT_FILE_PATH = "data/network_flows.csv"
BENIGN_FILE_PATH = "data/benign_flows.jsonl"
SCAN_FILE = "data/scan_flows.jsonl"


with open(BENIGN_FILE_PATH,'r') as file:
    for line in file:
        flow = json.loads(line)
        flow["label"] = "BENGIN"
        flows.append(flow)

with open(SCAN_FILE,'r') as file:
    for line in file:
        flow = json.loads(line)
        flow["label"] = "SCAN"
        flows.append(flow)


dataframe = pd.DataFrame(flows)
dataframe.to_csv(OUTPUT_FILE_PATH,index = False)
print(dataframe)