import json
from datetime import datetime, timedelta
import constants
import pytz
from dateutil import parser

# unused function to remove duplicate logs
def is_duplicate_suricata(existing_jsons, new_json):
    for json_obj in existing_jsons:
        if (
            json_obj['src_ip'] == new_json['src_ip'] and
            json_obj['dest_ip'] == new_json['dest_ip'] and
            json_obj['dest_port'] == new_json['dest_port'] and
            json_obj['proto'] == new_json['proto'] and
            json_obj['alert'].get('signature_id') == new_json['alert'].get('signature_id') and
            json_obj['direction'] == new_json['direction']
        ):
            if 'app_proto' in json_obj and 'app_proto' in new_json:
                if json_obj['app_proto'] == 'http' and new_json['app_proto'] == 'http':
                    if (
                        json_obj['http'].get('hostname') == new_json['http'].get('hostname') and
                        json_obj['http'].get('url') == new_json['http'].get('url') and
                        json_obj['http'].get('http_user_agent') == new_json['http'].get('http_user_agent') and
                        json_obj['http'].get('http_method') == new_json['http'].get('http_method')
                    ):
                        existing_time = datetime.strptime(json_obj['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                        new_time = datetime.strptime(new_json['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                        time_difference = new_time - existing_time
                        if abs(time_difference.total_seconds()) < constants.FILTER_THRESHOLD:
                            return True
                else:
                    existing_time = datetime.strptime(json_obj['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                    new_time = datetime.strptime(new_json['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                    time_difference = new_time - existing_time
                    if abs(time_difference.total_seconds()) < constants.FILTER_THRESHOLD:
                        return True
    return False

# unused function to remove duplicate logs
def is_duplicate_sysmon(existing_jsons, new_json):
    for json_obj in existing_jsons:
        existing_time = datetime.strptime(json_obj['TimeCreated_SystemTime'], '%Y-%m-%d %H:%M:%S.%f')
        new_time = datetime.strptime(new_json['TimeCreated_SystemTime'], '%Y-%m-%d %H:%M:%S.%f')
        time_difference = new_time - existing_time
                    
        if (
            json_obj['EventID'] == new_json['EventID'] and
            json_obj['Execution_ProcessID'] == new_json['Execution_ProcessID'] and
            json_obj['Security_UserID'] == new_json['Security_UserID'] and
            json_obj['EventData_RuleName'] == new_json['EventData_RuleName']
        ):
            if (
                'EventData_Protocol' in json_obj and 'EventData_Protocol' in new_json and
                'EventData_SourceIp' in json_obj and 'EventData_SourceIp' in new_json and
                'EventData_DestinationIp' in json_obj and 'EventData_DestinationIp' in new_json and
                'EventData_DestinationPort' in json_obj and 'EventData_DestinationPort' in new_json
            ):
                if (
                    json_obj['EventData_Protocol'] == new_json['EventData_Protocol'] and
                    json_obj['EventData_SourceIp'] == new_json['EventData_SourceIp'] and
                    json_obj['EventData_DestinationIp'] == new_json['EventData_DestinationIp'] and
                    json_obj['EventData_DestinationPort'] == new_json['EventData_DestinationPort']
                    ):
                    if abs(time_difference.total_seconds()) < constants.FILTER_THRESHOLD:
                        return True
            else:
                if abs(time_difference.total_seconds()) < constants.FILTER_THRESHOLD:
                    return True
    return False


# Function to filter Suricata alerts
def filter_suricata_alert(input_file, output_file):
    alert_events = []
    with open(input_file, 'r') as f:
        for line in f:
            # Parse each line as JSON
            json_obj = json.loads(line)

            # Check if the event_type is "alert"
            if json_obj.get('event_type') == "alert":
                # Convert timestamp format
                timestamp = json_obj.get('timestamp')
                if timestamp:
                    json_obj['timestamp'] = convert_timestamp(timestamp)


                alert_events.append(json_obj)

    print(len(alert_events))
    with open(output_file, 'w') as out_f:
        json.dump(alert_events, out_f, indent=4)



# adding hours to timestamps
def add_hours(ts, hours):
    dt = parser.parse(ts)  
    dt += timedelta(hours=hours)  
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")

# filtering of logs
def filter_sysmon_alert(input_file, output_file):
    alert_events = []
    with open(input_file, 'r') as f:
        for line in f:
            json_obj = json.loads(line)

            if json_obj.get('EventData_RuleName') != "-" or json_obj.get('EventData_RuleName') != "":
                json_obj['EventData_UtcTime'] = add_hours(json_obj['EventData_UtcTime'], 2)
                json_obj['TimeCreated_SystemTime'] = json_obj['EventData_UtcTime']
                alert_events.append(json_obj)
    
    print(len(alert_events))
    with open(output_file, 'w') as out_f:
        json.dump(alert_events, out_f, indent=4)       


def main(input_suricata, output_suricata, input_sysmon, output_sysmon):

    # Filter alert events and dump into a file
    filter_sysmon_alert(input_sysmon, output_sysmon)
    filter_suricata_alert(input_suricata, output_suricata)

    print("Filtered alert events have been dumped into {} and {}".format(output_suricata, output_sysmon))

