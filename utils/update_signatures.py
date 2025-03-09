# This script requests the current tracker list from Exodus Privacy and parses the data into a json required by the AppChecker
# WARN: this is to be run from the dir that contains the AppChecker main.py file
# WARN: this overwrites the tracker.json file in the subtasks dir, back it up if needed
import json
import urllib.request

# load json from exodus API
with urllib.request.urlopen(
    "https://reports.exodus-privacy.eu.org/api/trackers"
) as exodus_api:
    input_data = json.load(exodus_api)
# with open("tracker.json", "r") as json_input:
#     input_data = json.load(json_input)

# init list to collect trackers in
trackers_list = []

# iterate over input json
input_data = input_data["trackers"]
for tracker in input_data:
    tracker = input_data[tracker]

    # read values into a tracker instance dict
    tracker_instance = {
        "name": tracker["name"],
        "code_signature": tracker["code_signature"],
        "network_signature": tracker["network_signature"],
        "website": tracker["website"],
    }
    # collect tracker instance in list
    trackers_list.append(tracker_instance)

# wrap tracker list in dict
out_dict = {"trackers": trackers_list}

# write dict to output json
with open("subtasks/tracker.json", "w") as json_output:
    json.dump(out_dict, json_output, indent=2)
