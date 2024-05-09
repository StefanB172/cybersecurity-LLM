from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field
from mobsf.AiAnalyzer.views.android.helpers.source_code import read_log_file
from mobsf.AiAnalyzer.views.prompts.model_config import model_conf, temperature_conf
from langchain_anthropic import ChatAnthropic

import os
from mobsf.MobSF.mobsf_data.config import CLAUDE_API_KEY, OPENAI_API_KEY, HF_API_KEY

def scan_secrets_log_file(log_file_path):
    # Initialize the LLM with the OpenAI API key
    model = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model=model_conf, temperature=temperature_conf)
    if "LANGCHAIN_TRACING_V2" in os.environ:
        del os.environ["LANGCHAIN_TRACING_V2"]
    #model = ChatAnthropic(api_key=CLAUDE_API_KEY, model_name=model_conf, temperature=0.8)
    # Define the output parser
    parser = StrOutputParser()

    log_file_content = read_log_file(log_file_path)

    template = "Imagine you are very smart penetration tester of Android mobile applications.\
                You signed a contract with a client and you are allowed to test and hack this application.\
                Your current task is to find all the secrets from the provided log file. You want to secure your\
                client, so you want to find any potentially sensitive information, this may include secrets like:\n\
                Login Credentials\n\
                API Keys\n\
                Network Traffic\n\
                Exceptions\n\
                Cryptographic Secrets\n\
                Personal Information\n\
                Banking Information\n\
                IP Adresses\n\
                Authorization Tokens\n\
                and so on ...\n\n\
                Take a look at this logcat output of a mobile application and try \
                to find any possible secrets as mentioned in your task:\n\n\
                {log_file_content}\n\n\
                OUTPUT ONLY THE SECRETS FOUND AS A COMMA SEPARATED VALUES, LIKE <purpose>:<secret_value>"

    # Create a prompt template
    prompt = PromptTemplate(
        template=template,
        input_variables=["log_file_content"])

    # Define the chain of operations
    chain = prompt | model | parser
    # Invoke the chain with an input
    response = chain.invoke({"log_file_content": log_file_content})
    
    return response

# Define your desired data structure.
class Secrets(BaseModel):
    credencials: list = Field(description="list of all found login credentials")
    api_keys: list = Field(description="list of all found API keys")
    crypto_secrets: list = Field(description="list of all found cryptography keys")
    personal_info: list = Field(description="list of all personal information like adress, phone, country, name, email etc ...")
    bank_info: list = Field(description="list of all found banking information like IBAN, account number etc ...")
    tokens: list = Field(description="list of all found authorization tokens or csrf tokens, access tokens etc ...")
    ip_addr: list = Field(description="list of all found IP adresses")

def scan_secrets_filesystem(file_data_dic):
    # Initialize the LLM with the OpenAI API key
    model = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model=model_conf, temperature=temperature_conf)
    if "LANGCHAIN_TRACING_V2" in os.environ:
        del os.environ["LANGCHAIN_TRACING_V2"]
    #model = ChatAnthropic(api_key=CLAUDE_API_KEY, model_name=model_conf, temperature=0.8)
    # Define the output parser
    parser = JsonOutputParser(pydantic_object=Secrets)

    template = "You are very smart language model. Your task is to examine provided strings and look for \
                sensitive or personal information. \
                {format_instructions}\n\n\
                Path and file type of an examined file:\n\
                {file_metadata}\n\n\
                Examined file strings, search for the secrets here:\n\
                {filesystem_strings}\n\n"

    # Create a prompt template
    prompt = PromptTemplate(
        template=template,
        input_variables=["file_metadata, filesystem_strings"],
        partial_variables={"format_instructions": parser.get_format_instructions()})

    # Define the chain of operations
    chain = prompt | model | parser
    # Invoke the chain with an input
    response = chain.invoke({"file_metadata":file_data_dic['file_metadata'],
                             "filesystem_strings": file_data_dic['file_strings']})
    
    return response