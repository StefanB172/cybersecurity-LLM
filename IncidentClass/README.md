### A guide for launching and testing our solution in your own environment.

**Python** libraries must be installed for the system to function properly. We can install them using the following commands:
```sh
pip install openai
pip install flask
pip install markdown
pip install requests
```


After the libraries are installed, we can run the tool with the command:

```sh
python correlation.py
```

To convert Sysmon records from EVTX format to JSON, you need to download a tool [evtx-toolkit](https://github.com/MISP/evtx-toolkit/blob/main/README.md)
and use the following command:

```sh
python evtx\_dump.py sysmon.evtx --noepochconvert -o json > output.json
```

In case of using commercial models from OpenAI, it is necessary to purchase an API key on the site [OpenAI](https://openai.com/api/). 
This API key must later be inserted in the *constants.py* file into a variable called *API_KEY*.
In the case of a local LLM, it is necessary to download the [llama server](https://github.com/ggerganov/llama.cpp). 
After that, you need to download the selected LLM model from the site [Hugging face](https://huggingface.co/). 
The model can then be run as follows:

```sh
./server -m CESTA_K_MODELU
```

After installing the **Flask** framework, it is possible to start the web interface with the following command:

```sh
python backend.py
```
