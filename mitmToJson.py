# Simple script used to convert .mitm data to json

# Flow:
#   opens a .mitm file and reads the captured flows (requests/responses)
#   extracts the raw state data from each flow
#   writes everything to a json file, handling any bytes by converting them to readable strings


import sys
import json
import base64
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException

class MitmJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            try:
                return obj.decode('utf-8')
            except UnicodeDecodeError:
                return base64.b64encode(obj).decode('utf-8') # fallback to base64
        return super().default(obj)
    
def mitmToJson(mitmFile, jsonFile):
    flowsData = []
    with open(mitmFile, "rb") as f:
        fReader = io.FlowReader(f)
        try:
            for flow in fReader.stream():
                flowsData.append(flow.get_state()) #flow.get_state() extracts all internal/external data
        except FlowReadException as e:
            print(f"error reading flow file: {e}")
            sys.exit(1)
    with open(jsonFile, "w", encoding="utf-8") as f:
        json.dump(flowsData, f, indent=4, cls=MitmJSONEncoder)
    print(f"{len(flowsData)} flows written to {jsonFile}")
    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("python mitmToJson.py <input.mitm> <output.json>")
        sys.exit(1)
    mitmToJson(sys.argv[1], sys.argv[2])
