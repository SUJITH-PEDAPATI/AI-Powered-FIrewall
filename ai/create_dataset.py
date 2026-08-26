import json
import pandas as pd
flows = []

JSONL_FILE_PATH = "data/flows.jsonl"
CSV_FILE_PATH = "data/network_flows.csv"
with open(JSONL_FILE_PATH,'r') as file:
    for line in file:
        flow = json.loads(line)
        flows.append(flow)

dataframe = pd.DataFrame(flows)
dataframe.to_csv(CSV_FILE_PATH,index = False)
print(dataframe)