from pprint import pprint
import subprocess
import json

def callback(data):
    pprint(json.loads(data.replace("'", "\"")))

visit_buffer = []
while True:
    dmesg = subprocess.getoutput("dmesg")
    for msg in dmesg.split("\n"):
        if msg and msg not in visit_buffer:
            visit_buffer.append(msg)
            callback(msg.split("Performance and Diagnostic Metrics//")[-1])