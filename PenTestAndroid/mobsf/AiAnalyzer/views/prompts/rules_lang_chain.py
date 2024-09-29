from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate,PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field
import os
from langchain_anthropic import ChatAnthropic

from mobsf.AiAnalyzer.views.prompts.model_config import model_conf, temperature_conf

from mobsf.MobSF.mobsf_data.config import CLAUDE_API_KEY, OPENAI_API_KEY, HF_API_KEY


def scan_logs_code(file_content, file_path):
    try:
        # Initialize the LLM with the OpenAI API key
        model = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model=model_conf, temperature=temperature_conf)
        if "LANGCHAIN_TRACING_V2" in os.environ:
            del os.environ["LANGCHAIN_TRACING_V2"]
        #model = ChatAnthropic(api_key=CLAUDE_API_KEY, model_name=model_conf, temperature=0.8)
        # Define the output parser
        parser = StrOutputParser()

        template = "Is this mobile application code logging some sensitive information ?\
                    If yes answer with list of sensitive information being logged. \
                    If no, answer with a string 'aaa'. \
                    NO OTHER DESCRIPTION.\
                    \n\n\
                    {file_content}\n\n"

        # Create a prompt template
        prompt = PromptTemplate(
            template=template,
            input_variables=["file_content"]
        )

        # Define the chain of operations
        chain = prompt | model | parser
        # Invoke the chain with an input
        llm_string_response = chain.invoke({"file_content": file_content})

        # Split the path into components
        path_parts = file_path.split(os.sep)
        # Extract the last three segments
        last_three_segments = path_parts[-3:]
        # Optional: Join them back into a path string
        last_three_path = os.path.join(*last_three_segments)

        response = {}
        response['file_path'] = last_three_path
        response['logged_secrets'] = llm_string_response
        return response
    except Exception as e:
        print(e)
        print('rule log langchain')
        return {}



class Finding(BaseModel):
    vulnerable: bool = Field(description="true if is vulnerable, false if it is NOT vulnerable")
    issue: str = Field(description="two-sentence description of found vulnerability")
    snippet: str = Field(description="one or more line snippet of vulnerable code, if the vulnerability is found")


def scan_vuln_code(rule, file_content, file_path):
    try:
        # Initialize the LLM with the OpenAI API key
        model = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model=model_conf, temperature=temperature_conf)
        if "LANGCHAIN_TRACING_V2" in os.environ:
            del os.environ["LANGCHAIN_TRACING_V2"]
        #model = ChatAnthropic(api_key=CLAUDE_API_KEY, model_name=model_conf, temperature=0.8)
        # Define the output parser
        parser = JsonOutputParser(pydantic_object=Finding)

        template = "You are very smart penetration tester of Android mobile applications.\
                    You signed a contract with a client and you are allowed to test and hack this application.\
                    Using Semgrep rule, we identified a possible vulnerable code. Your task is to verify the \n\
                    code provided, if the following issue is present in the code. \n\
                    {format_instructions}\n\n\
                    Issue to verify: \n\
                    {rule_message}\n\n\
                    Enumerate the following app source code, does the reported issue introduces a security\n\
                    risk ? \
                    {file_content}\n\n\n\
                    DO NOT REPORT POTENTIAL VULNERABILITIES.\n\
                    Report a vulnerability only if the code provided is vulnerable.\n\
                    Do not report general recommendations.\
                    NO OTHER DESCRIPTION, ONLY GIVE AN OUTPUT AS YOU WERE INSTRUCTED!"

        # Create a prompt template
        prompt = PromptTemplate(
            template=template,
            input_variables=["rule_message, file_content"],
            partial_variables={"format_instructions": parser.get_format_instructions()}
        )

        # Define the chain of operations
        chain = prompt | model | parser
        # Invoke the chain with an input
        response = chain.invoke({"rule_message": rule.extra.message,
                                "file_content":file_content})
        

        # Split the path into components
        path_parts = file_path.split(os.sep)
        # Extract the last three segments
        last_three_segments = path_parts[-3:]
        # Optional: Join them back into a path string
        last_three_path = os.path.join(*last_three_segments)
        
        rule_id = rule.check_id
        # Find the last dot
        last_dot_index = rule_id.rfind('.')

        # Extract the part after the last dot
        if last_dot_index != -1:  # Ensure that there was at least one dot
            part_after_last_dot = rule_id[last_dot_index + 1:]
        else:
            part_after_last_dot = rule_id  # If no dot is found, return the whole text

        response['rule_message'] = rule.extra.message
        response['rule_id'] = part_after_last_dot
        response['file_path'] = last_three_path

        return response
    except Exception as e:
        print(e)
        print('rule vuln langchain')
        return {}