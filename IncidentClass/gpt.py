import openai
import json
import constants
import time
import requests

client = openai.OpenAI(api_key=constants.API_KEY)

# loading content of a file
def load_json_array(file_path):
    try:
        with open(file_path, 'r') as file:
            json_array = json.load(file)
        return json_array
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON in file '{file_path}'.")
        return None

# function to offer abbility  to send prompts to openai
def gpt_request(message):
    try:    
        response = client.chat.completions.create(
            model=constants.GPT_MODEL,
            messages=[
                    {"role": "system", "content": "You are a security specialist who replies with great precision."},
                    {"role": "user", "content": message}
                    ]
            )
        return response.choices[0].message.content
    except Exception as e:
        print('[!] GPT ERROR: {}.'.format(e))
    time.sleep(5)
    #print(response.choices[0].message.content)
    return ""

# function to offer abbility to send prompts to local models
def llama_request(message):
    url = f"http://127.0.0.1:8080/completion"
    req_json = {
        "stream": False,
        "n_predict": 750,
        "temperature": 0.7,
        "stop": [
            "</s>",
            "L:",
            "U:"
        ],
        "repeat_last_n": 256,
        "repeat_penalty": 1.18,
        "top_k": 40,
        "top_p": 0.95,
        "tfs_z": 1,
        "typical_p": 1,
        "presence_penalty": 0,
        "frequency_penalty": 0,
        "mirostat": 0,
        "mirostat_tau": 5,
        "mirostat_eta": 0.1,
        "grammar": "",
        "n_probs": 0,
        "prompt":"This is a conversation between U and L.\nL is a security specialist and answers with great precision.\nU:{}\n L:".format(message)
    }    
    try:
        res = requests.post(url, json=req_json)
        result = res.json()["content"]
        time.sleep(5)
        return result
    except:
        print('Server not running.')
        exit(0)


        