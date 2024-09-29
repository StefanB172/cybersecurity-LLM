from flask import Flask, render_template, jsonify,request
import json
import constants
import time
from markdown import Markdown
import re

app = Flask(__name__)

technique_pattern = r'Technique: (.*?)$'

suricata_all = []
sysmon_all = []
correlated_all = []

# loading logs from files
def load_logs():
    global sysmon_all, suricata_all, correlated_all
    try:
        with open('attack/alerts_sysmon.json', 'r') as file:
            sysmon_all = json.load(file)
    except e:
        print('[!] Sysmon file not available.')
        exit(1)

    try:
        with open('attack/alerts_suricata.json', 'r') as file2:
            suricata_all = json.load(file2)
    except e:
        print('[!] Suricata file not available.')
        exit(1)

    try:
        with open('correlated.json', 'r') as file3:
            correlated_all = json.load(file3)
    except e:
        print('[!] Correlated data file not available.')
        exit(1)


# extracting key attributes for web appearance
def get_attributes_suricata(data):
    attributes = []
    attributes.append(data['timestamp'])
    attributes.append(data['event_type'].upper())
    attributes.append(data['proto'])
    attributes.append(data['alert'].get('category'))
    attributes.append(data['alert'].get('signature'))
    return attributes

# extracting key attributes for web appearance
def get_attributes_sysmon(data):
    attributes = []
    attributes.append(data['TimeCreated_SystemTime'])
    attributes.append(data['Channel'])
    if 'EventData_RuleName' in data:
        attributes.append(data['EventData_RuleName'])
    else:
        attributes.append('-')
    return attributes

# extracting key attributes for web appearance
def get_attributes_correlated(data):
    attributes = []
    #attributes.append(data['suricata_logs'].get('timestamp'))
    #attributes.append(data['suricata_logs'].get('proto'))
    #attributes.append(data['suricata_log'].get('alert')['signature_id'])
    #attributes.append(data['sysmon_log'].get('EventData_RuleName').split(',')[1].split('=')[1])
    #attributes.append(data['GPT mittre'][:50] + '...')
    if 'start time' in data and 'end time' in data:
        attributes.append(data['start time'])
        attributes.append(data['end time'])
    technique_match = re.search(technique_pattern, data['GPT mittre'], re.MULTILINE)
    if technique_match:
        technique = technique_match.group(1).strip()
        attributes.append(technique)
    else:
        attributes.append(data['GPT mittre'][:50] + '...')

    return attributes


# displaying all metadata of the logs
def print_full_json(data):
    html = '<div class="json">'
    html += '<ul>'
    for key, value in data.items():
        html += f'<li><span class="key"><strong>{key}</strong>: </span>'
        if isinstance(value, dict):
            html += print_full_json(value)
        elif isinstance(value, list):
            html += '<ul>'
            for item in value:
                html += f'<li>{item}</li>'
            html += '</ul>'
        else:
            html += str(value)
        html += '</li>'
    html += '</ul>'
    html += '</div>'
    return html

# displaying key attributes
def print_suricata(data, size):
    html = "<div>"
    i = 0
    for item in data:
        if i < size:
            attributes = get_attributes_suricata(item)
            html += f"""
            <button type='button' class='collapsible'>
            <h7>{attributes[0]}</h7>
            <h7>{attributes[1]}</h7>
            <h7>{attributes[2]}</h7>
            <h7>{attributes[3]}</h7>
            <h7>{attributes[4]}</h7>
            </button>
            """
            html += f"<div class='content'>"
            html += print_full_json(item)
            html += f"</div>"
        else:
            break
        i += 1

    html += "</div>"
    return html

# displaying key attributes
def print_sysmon(data, size):
    html = "<div>"
    i = 0
    for item in data:
        if i < size:
            attributes = get_attributes_sysmon(item)
            html += f"""
            <button type='button' class='collapsible'>
            <h7>{attributes[0]}</h7>
            <h7>{attributes[1]}</h7>
            <h7>{attributes[2]}</h7>
            </button>
            """
            html += f"<div class='content'>"
            html += print_full_json(item)
            html += f"</div>"
        else:
            break
        i += 1

    html += "</div>"
    return html

# displaying key attributes
def print_correlated(data, size):
    html = "<div>"
    i = 0
    for item in data:
        if i < size:
            attributes = get_attributes_correlated(item)
            md = Markdown()
            gpt_message = item['GPT mittre']
            if 'ignore' not in gpt_message.lower() and 'not a security incident' not in gpt_message.lower() and 'no security incident' not in gpt_message.lower():
                gpt_info = item['GPT info']
                html_text = md.convert(gpt_message)
                html_text2 = md.convert(gpt_info)
                item['GPT mittre'] = html_text
                item['GPT info'] = html_text2
                if len(attributes) > 1:

                    html += f"""
                    <button type='button' class='collapsible'>
                    <h7>{attributes[0]}</h7>
                    <h7>{attributes[1]}</h7>
                    <h7>{attributes[2]}</h7>
                    </button>
                    """
                else:
                    html += f"""
                    <button type='button' class='collapsible'>
                    <h7>{attributes[0]}</h7>
                    </button>
                    """
            html += f"<div class='content'>"
            html += print_full_json(item)
            html += f"</div>"
        else:
            break
        i += 1

    html += "</div>"
    return html


@app.route('/')
def index():
    names = ['Suricata','Sysmon','Correlated']
    counts = [len(suricata_all), len(sysmon_all), len(correlated_all)]
    return render_template('index.html', names=names, lengths=counts)


@app.route('/suricata', methods=['GET'])
def suricata_json_data():
    args = request.args
    size = args.get('size', default=constants.DEFAULT_SIZE, type=int)
    if size > len(suricata_all):
        size = len(suricata_all)
    visualized_data = print_suricata(suricata_all, size)
    return render_template('suricata.html', visualized_data=visualized_data, size=len(suricata_all))


@app.route('/sysmon', methods=['GET'])
def sysmon_json_data():
    args = request.args
    size = args.get('size', default=constants.DEFAULT_SIZE, type=int)
    if size > len(sysmon_all):
        size = len(sysmon_all)
    visualized_data = print_sysmon(sysmon_all, size)
    return render_template('sysmon.html', visualized_data=visualized_data, size=len(sysmon_all))


@app.route('/correlated', methods=['GET'])
def correlated_json_data():
    args = request.args
    size = args.get('size', default=constants.DEFAULT_SIZE, type=int)
    if size > len(correlated_all):
        size = len(correlated_all)
    visualized_data = print_correlated(correlated_all, size)
    return render_template('correlated.html', visualized_data=visualized_data, size=len(correlated_all))


@app.route('/refresh')
def refresh():
    load_logs()
    names = ['Suricata','Sysmon','Correlated']
    counts = [len(suricata_all), len(sysmon_all), len(correlated_all)]
    return render_template('index.html', names=names, lengths=counts)


if __name__ == '__main__':
    load_logs()
    app.run(debug=True)
    while True:
        time.sleep(10)
        load_logs()