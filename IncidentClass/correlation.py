import json
from datetime import datetime, timedelta
import constants
from dateutil import parser
import pytz
import gpt
import copy
import ipaddress
import time
import events_filter


def count_tokens(text):
    return len(text.split())

# function for IP address correlation
def correlate_ip(suricata, sysmon):
    suricata_src_ips = []
    suricata_dst_ips = []
    for i in suricata:
        if i['src_ip'] not in suricata_src_ips:
            suricata_src_ips.append(i['src_ip'])
        if i['dest_ip'] not in suricata_dst_ips:
            suricata_dst_ips.append(i['dest_ip'])
    
    for i in range(len(suricata_src_ips)):
        for item in sysmon.values():
            if suricata_src_ips[i] == item:
                return True
    for i in range(len(suricata_dst_ips)):
        for item in sysmon.values():
            if suricata_dst_ips[i] == item:
                return True
    return False

# function for HTTP address correlation
def correlate_http(suricata, sysmon, time_difference):
    if 'http' in suricata:
        hostname = suricata['http'].get('hostname')
        url = suricata['http'].get('url')
        for item in sysmon.values():
            if hostname in item and time_difference <= timedelta(seconds=constants.CORRELATION_THRESHOLD):
                return True
            if url in item and time_difference <= timedelta(seconds=constants.CORRELATION_THRESHOLD):
                return True

    if 'files' in suricata:
        file = suricata['files'].get('filename')
        if file in item and time_difference <= timedelta(seconds=constants.CORRELATION_THRESHOLD):
            return True
        
    return False

# function to load logs from file
def load_logs(file_path):
    try:
        with open(file_path, 'r') as f:
            logs = json.load(f)
        return logs
    except e:
        print('[!] File {} not found.'.format(file_path))
        exit(1)

# binary seach algorithm to find a log in a batch of logs
def binary_search(logs, target_time, time_threshold):
    left = 0
    right = len(logs) - 1

    while left <= right:
        mid = left + (right - left) // 2
        mid_time = datetime.strptime(logs[mid]['EventData_UtcTime'], "%Y-%m-%d %H:%M:%S.%f")
        time_difference = abs(mid_time - target_time)
        if time_difference <= time_threshold:
            return mid
        elif mid_time < target_time:
            left = mid + 1
        else:
            right = mid - 1

    return -1

# converting time from utc to cet
def convert_utc_to_cet(utc_ts):
    # Define time zones
    utc = pytz.utc
    cet = pytz.timezone('CET')

    # Parse UTC timestamp and localize it to UTC time zone
    utc_dt = datetime.strptime(utc_ts, '%Y-%m-%d %H:%M:%S.%f')
    utc_dt = utc.localize(utc_dt)

    # Convert to CET time zone
    cet_dt = utc_dt.astimezone(cet)

    return cet_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


# unused function
# used for primare testing of logs correlation
def correlate_logs(suricata_logs, sysmon_logs, time_threshold_seconds=constants.CORRELATION_THRESHOLD):
    correlated_logs = []

    for suricata_log in suricata_logs:
        suricata_time = datetime.strptime(suricata_log['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
        #suricata_alert = suricata_log.get('alert', {})
        suricata_src_ip = suricata_log['src_ip']
        suricata_dst_ip = suricata_log['dest_ip']
        #suricata_process_image = suricata_alert.get('process_image')

        #if suricata_process_id is None and suricata_process_image is None:
        #    continue  # Skip this suricata log if it doesn't contain process or image information

        correlated_sysmon_logs = []

        index = binary_search(sysmon_logs, suricata_time, timedelta(seconds=time_threshold_seconds))
        # Iterate through all Sysmon logs
        while index != -1 and index < len(sysmon_logs):
            sysmon_log = sysmon_logs[index]
            sysmon_time = datetime.strptime(sysmon_log['TimeCreated_SystemTime'], "%Y-%m-%d %H:%M:%S.%f")
            time_difference = abs(sysmon_time - suricata_time)
            if correlate_ip(suricata_log, sysmon_log):
                correlated_sysmon_logs.append(sysmon_log)
            if correlate_http(suricata_log, sysmon_log, time_difference):
                correlated_sysmon_logs.append(sysmon_log)
            else:
            # Check if the Sysmon log is within the threshold and matches the Suricata alert
                if time_difference > timedelta(seconds=time_threshold_seconds):
                    break

            index += 1

        if correlated_sysmon_logs:
            correlated_logs.append({
                'suricata_log': suricata_log,
                'sysmon_logs': correlated_sysmon_logs
            })

    return correlated_logs

# main correlation function
def correlate(suricata_logs, sysmon_logs, time_threshold_seconds=constants.CORRELATION_THRESHOLD):
    start_time = datetime.strptime(suricata_logs[0]['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
    print(start_time)
    batch_suricata = []
    tmp = []
    # grouping Suricata logs
    for suricata_log in suricata_logs:
        suricata_time = datetime.strptime(suricata_log['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
        time_difference = abs(suricata_time - start_time)
        if time_difference < timedelta(seconds=time_threshold_seconds):
            tmp.append(suricata_log)
        else:
            if len(tmp) > 0:
                batch_suricata.append(tmp)
                tmp = []
            start_time = datetime.strptime(suricata_log['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
    
    #print(len(batch_suricata))
    count = 0
    batch_symon = []
    # grouping Sysmon logs
    for logs in batch_suricata:
        correlated_sysmon_logs = []
        start_time = datetime.strptime(logs[0]['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
        
        index = binary_search(sysmon_logs, start_time, timedelta(seconds=constants.SYSMON_THRESHOLD))
        while index != -1 and index < len(sysmon_logs):
            sysmon_log = sysmon_logs[index]
            sysmon_time = datetime.strptime(sysmon_log['EventData_UtcTime'], "%Y-%m-%d %H:%M:%S.%f")
            time_difference = abs(sysmon_time - start_time)
            if time_difference <= timedelta(seconds=constants.SYSMON_THRESHOLD):
                if 'EventData_SourceIp' in sysmon_log or 'EventData_DestinationIp' in sysmon_log:
                    if correlate_ip(logs, sysmon_log):
                        correlated_sysmon_logs.append(sysmon_log)
            else:
                break

            index += 1
        batch_symon.append(correlated_sysmon_logs)
        #print("[{}]  Suricata: {}  |  Sysmon: {}".format(count,len(logs),len(correlated_sysmon_logs)))
        count += 1
    
    dic_suricata, dic_sysmon = reduce_logs(batch_suricata,batch_symon)
    
    final_output = []
    execution_time_start = time.time()
    conf_size = 0
    # sending log batches to LLM
    for i in range(len(batch_suricata)):
        if i > -1:
            print('\n\n[{}] GPT Logs Info ===========\n\n'.format(i))
            times = []
            for key, value in dic_suricata[i].items():
                times.append(value['start_time'])

            conf_message = get_llm_alert_info(dic_suricata[i], dic_sysmon[i])
            conf_size += get_llm_alert_info(dic_suricata[i], dic_sysmon[i])

            print(conf_message)
            print('\n\n[{}] GPT Attack Info ===========\n\n'.format(i))
            print("Start time: {}".format(times[0]))
            print("End time: {}".format(times[-1]))
            #final_message = ''
            final_message = get_llm_classification(dic_suricata[i], dic_sysmon[i], conf_message)
            print(final_message)
            final_output.append({
                        'start time': times[0],
                        'end time': times[-1],
                        'GPT info':conf_message,
                        'GPT mittre':final_message,
                        'suricata_logs': batch_suricata[i],
                        'sysmon_logs': batch_symon[i]
                        #'suricata_logs': batch_suricata[i],
                        #'sysmon_logs': batch_symon[i]
                    })
    execution_end_time = time.time()
    print('[*] TIME: {} seconds'.format(execution_end_time - execution_time_start))
    print('[+] TOTAL: {}'.format(conf_size / len(dic_suricata)))
    return final_output

# calling LLM to idenitfy and classify occured incidents in a time window
def get_llm_classification(dic_suricata, dic_sysmon, conf_message):
    message = "Analyze if a security incident is happening based on provided logs which happened during {} seconds window.".format(constants.FILTER_THRESHOLD)
    message += " Suricata logs that were identified:  "
    for key, value in dic_suricata.items():
        message += " LOG: \n"
        sur_log = value['log']
        sur_occur = value['occurrences']
        sur_log = remove_suricata_attr(sur_log)
        message += json.dumps(sur_log)
        message += "\nOCCURRED {} times.\n".format(sur_occur)

    message += "  Sysmon logs that were identified: "
    for key, value in dic_sysmon.items():
        message += " LOG: \n"
        sys_log = value['log']
        sys_occur = value['occurrences']
        sys_log = remove_sysmon_attr(sys_log)
        message += json.dumps(sys_log)
        message += "\nOCCURRED {} times.\n".format(sys_occur)

    message += '''
        In case of a security incident, your task is to:
        - Decide if the logs represent a security incident/attack.
        - Based on Mitre Att&ck, tell me which technique best describes the discovered incident.
        - Based on Mitre Att&ck, tell me which procedures were used during the incident.
        - Based on choosen Mitre Att&ck technique, tell me which attack tactic/kill chain stage does the technique belongs to.
        - Give me score from 1 to 10 how critical it is.
        Remember to take into account also the number of occurrences of each log.
        Try to reply as precisely as possible. Reply just with the Mitre Att&ck information and score. In case it is NOT a incident, *ignore* the previous commands.
    '''
    message += ". For the analysis use also following additional information: {}".format(conf_message)
    return gpt.gpt_request(message=message)

# get details about what happended from the provided logs
def get_llm_alert_info(dic_suricata, dic_sysmon):
    message = "Your task is to perform log analysis based JUST on provided logs which happened during {} seconds window.".format(constants.FILTER_THRESHOLD)
    message += " Suricata logs that were identified:  "
    for key, value in dic_suricata.items():
        message += " LOG: \n"
        sur_log = value['log']
        sur_occur = value['occurrences']
        sur_log = remove_suricata_attr(sur_log)
        message += json.dumps(sur_log)
        message += "\nOCCURRED {} times.\n".format(sur_occur)

    message += "  Sysmon logs that were identified: "
    for key, value in dic_sysmon.items():
        message += " LOG: \n"
        sys_log = value['log']
        sys_occur = value['occurrences']
        sys_log = remove_sysmon_attr(sys_log)
        message += json.dumps(sys_log)
        message += "\nOCCURRED {} times.\n".format(sys_occur)

    message += '''
        Your task is to:
            - Analyze the suricata and sysmon logs if they have anything in common. In case sysmon/suricata logs are missing, continue without them.
            - Identify if the logs represent a security incident. Take into account also the number of occurences of each log.
            - Describe the potential incident.
            - Perform threat intelligence search on found IoCs.
        Use only provided information. Remember to reply shortly and precisely.V tomto
    '''
    #print("[*] CONFIRMATION:\n {}".format(message))
    size = count_tokens(message)
    print('[+] Size: {}'.format(size))
    return gpt.gpt_request(message=message)
    #return gpt2.llama_request(message=message)


# removing unrelevant data
def remove_sysmon_attr(log):
    if 'Provider_Guid' in log:
        log.pop('Provider_Guid')
    if 'EventID_Qualifiers' in log:
        log.pop('EventID_Qualifiers')
    if 'Version' in log:
        log.pop('Version')
    if 'Opcode' in log:
        log.pop('Opcode')
    if 'Keywords' in log:
        log.pop('Keywords')
    if 'TimeCreated' in log:
        log.pop('TimeCreated')
   
    return log

# removing unrelevant data
def remove_suricata_attr(log):
    if 'flow_id' in log:
        log.pop('flow_id')
    if 'in_iface' in log:
        log.pop('in_iface')
    if 'tx_id' in log:
        log.pop('tx_id')
    if 'gid' in log['alert']:
        log['alert'].pop('gid')
    if 'signature_id' in log['alert']:
        log['alert'].pop('signature_id')
    if 'rev' in log['alert']:
        log['alert'].pop('rev')
    return log
    

def reduce_logs(arr_suricata, arr_sysmon):
    dif_suricata = []
    dif_sysmon = []
    for i in range(len(arr_suricata)):
        dic_suricata = {}
        dic_sysmon = {}
        #print("[{}]: ================================= \n".format(i))
        # reducing few attributes
        for j in arr_suricata[i]:
            tmp = copy.deepcopy(j)
            if 'timestamp' in tmp:
                tmp.pop('timestamp')
            if 'flow_id' in tmp:
                tmp.pop('flow_id')
            if 'flow' in tmp:
                tmp.pop('flow')
            if 'metadata' in tmp:
                tmp.pop('metadata')
            if 'in_iface' in tmp:
                tmp.pop('in_iface')
            tmp = json.dumps(tmp)
            if tmp not in dic_suricata:
                dic_suricata[tmp] = {'log': j, 'occurrences': 1, 'start_time': j['timestamp']}
            else:
                dic_suricata[tmp]['occurrences'] += 1

            tmp = ""

        for k in arr_sysmon[i]:
            tmp = copy.deepcopy(k)
            if 'TimeCreated_SystemTime' in tmp:
                tmp.pop('TimeCreated_SystemTime')
            if 'EventData_UtcTime' in tmp:
                tmp.pop('EventData_UtcTime')
            
            tmp = json.dumps(tmp)
            if tmp not in dic_sysmon:
                dic_sysmon[tmp] = {'log': k, 'occurrences': 1, 'start_time':k['TimeCreated_SystemTime']}
            else:
                dic_sysmon[tmp]['occurrences'] += 1
            
            '''#tmp = json.dumps(tmp)
            if tmp['EventData_RuleName'] not in dic_sysmon:
                dic_sysmon[tmp['EventData_RuleName']] = {'log': k, 'occurrences': 1, 'start_time':k['TimeCreated_SystemTime']}
            else:
                dic_sysmon[tmp['EventData_RuleName']]['occurrences'] += 1'''

            tmp = ""
        
        dif_suricata.append(dic_suricata)
        dif_sysmon.append(dic_sysmon)
    return dif_suricata, dif_sysmon
            

if __name__ == "__main__":

    print('[*] Filtering sysmon and suricata logs...\n')
    input_sysmon = input('Enter Sysmon JSON file: ')
    output_sysmon = 'sysmon_alerts.json'
    input_suricata = input('Enter Suricata eve.json')
    output_suricata = 'suricata_alerts.json'
    events_filter.main(input_suricata, output_suricata, input_sysmon, output_sysmon)

    # Load suricata and sysmon logs
    suricata_logs = load_logs('suricata_alerts.json')
    sysmon_logs = load_logs('sysmon_alerts.json')
    print('[*] Correlation in progress....\n')
    # Correlate the logs
    correlated_logs = correlate(suricata_logs, sysmon_logs)

    print('[*] Dumping into a file....\n')
    # Store the correlated logs into a file
    output_file = 'correlated.json'
    print(len(correlated_logs))
    with open(output_file, 'w') as f:
        json.dump(correlated_logs, f, indent=4)
    print('[+] File output.json created!')
