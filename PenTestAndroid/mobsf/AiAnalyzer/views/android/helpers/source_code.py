import os
import re


def read_java_file(file_path):
    # Open the file in read mode ('r')
    with open(file_path, 'r') as file:
        # Read the contents of the file
        java_file_content = file.read()

    # Remove single-line comments
    java_file_content = re.sub(r'//.*', '', java_file_content)
    # Remove multi-line comments
    java_file_content = re.sub(r'/\*.*?\*/', '', java_file_content, flags=re.DOTALL)
    # Remove import statements
    java_file_content = re.sub(r'^\s*import.*', '', java_file_content, flags=re.MULTILINE)
    # Remove package declarations
    java_file_content = re.sub(r'^\s*package.*', '', java_file_content, flags=re.MULTILINE)

    # Truncate content if it exceeds 50,000 characters
    if len(java_file_content) > 30000:
        java_file_content = java_file_content[:30000]

    return java_file_content

def read_log_file(file_path):
    # Open the file in read mode ('r')
    with open(file_path, 'r') as file:
        # Read the contents of the file
        log_file_content = file.read()
    return log_file_content