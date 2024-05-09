from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate,PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain_anthropic import ChatAnthropic
import os, requests
from mobsf.AiAnalyzer.views.prompts.model_config import model_conf, temperature_conf
from mobsf.MobSF.mobsf_data.config import OPENAI_API_KEY, CLAUDE_API_KEY, HF_API_KEY

# Define your desired data structure.
class Result(BaseModel):
    vulnerable: bool = Field(description="Is component vulnerable ?")
    issues: list = Field(description="list of one-sentence description of found vulnerabilities.")
    exploits: list = Field(description="list of all possible 'adb' commands to exploit found vulnerability")

def scan_exp_components(component_definition, component_code):
    try:
        # Initialize the LLM with the OpenAI API key
        model = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model=model_conf, temperature=0.6)
        if "LANGCHAIN_TRACING_V2" in os.environ:
            del os.environ["LANGCHAIN_TRACING_V2"]
        #Anthrophic
        #model = ChatAnthropic(api_key=CLAUDE_API_KEY, model_name=model_conf, temperature=0.8)

        # Define the output parser
        parser = JsonOutputParser(pydantic_object=Result)

        template = "You are very smart penetration tester of Android mobile applications.\
                    You signed a contract with a client and you are allowed to test and hack this application.\
                    Your current task is to find the vulnerabilities in the provided code and help to secure tested\
                    mobile application.\n\
                    {format_instructions}\n\n\
                    Take a look at this exported component code.\n\n\
                    AndroidManifest.xml:\n\
                    {component_definition}\n\
                    Exported component code:\n\
                    {component_code}\n\n\
                    DO NOT REPORT POTENTIAL VULNERABILITIES, ONLY REPORT VULNERABILITIES WITH SEVERITY HIGH AND CRITICAL.\
                    IF AN ACTIVITY IS EXPORTED THAT DOESNT MEAN ITS VULNERABLE \
                    NO OTHER DESCRIPTION, ONLY GIVE A JSON OUTPUT AS YOU WERE INSTRUCTED!"

        # Create a prompt template
        prompt = PromptTemplate(
            template=template,
            input_variables=["component_definition, component_code"],
            partial_variables={"format_instructions": parser.get_format_instructions()}
        )

        # Define the chain of operations
        chain = prompt | model | parser
        # Invoke the chain with an input
        response = chain.invoke({"component_definition": component_definition,
                                    "component_code":component_code})
        
        response['component_definition'] = component_definition
        response['component_code'] = component_code
    except Exception as e:
        print(e)
        print('exp comp langchain')
        return {}
    return response
