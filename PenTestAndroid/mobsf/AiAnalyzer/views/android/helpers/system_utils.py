import json
import subprocess
import os

def extract_strings_from_directory(directory_path, output_file_path, min_length=6):
    # Check if the specified directory exists
    if not os.path.isdir(directory_path):
        print("Directory does not exist:", directory_path)
        return
    
    # Clear file
    with open(output_file_path, "w") as out_file:
        out_file.write('')

    # Iterate over all files in the specified directory
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            # Check if it's a regular file (not a directory or a link)
            if os.path.isfile(file_path):
                print(f"Extracting strings from: {file_path}")
                try:
                    # Call the strings utility and capture the output
                    result = subprocess.run(['strings', '-n', str(min_length), file_path], capture_output=True, text=True)
                    output = result.stdout
                    
                    # Example: Save to a file
                    with open(output_file_path, "a") as out_file:
                        out_file.write(output)
                except Exception as e:
                    print(f"Failed to extract strings from {file_path}: {e}")

def extract_file_data(file_path, min_length=8):
    try:
        results = {}
        results['file_path'] = file_path
        # Call the strings utility and capture the output
        strings = subprocess.run(['strings', '-n', str(min_length), file_path],
                                 capture_output=True, text=True)
        results['file_strings'] = strings.stdout

        # Call the file utility and capture the metadata
        metadata = subprocess.run(['file', file_path],
                                   stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
        # Check if the command was successful
        if metadata.returncode != 0:
            # Command failed, output the error
            print(f"Error: {metadata.stderr.strip()}")

        results['file_metadata'] = metadata.stdout
        return results
    except Exception as e:
        print(f"Failed to extract strings from {file_path}: {e}")


def create_app_data_folders(base_path):
    # List of directories to check
    directories = ['filesystem', 'logs', 'results']

    # Check each directory and create if not exists
    for directory in directories:
        full_path = os.path.join(base_path, directory)
        if not os.path.exists(full_path):
            os.makedirs(full_path)

    # Additional directories inside 'filesystem'
    filesystem_path = os.path.join(base_path, 'filesystem')
    additional_dirs = ['internal', 'external']

    for adir in additional_dirs:
        adir_full_path = os.path.join(filesystem_path, adir)
        if not os.path.exists(adir_full_path):
            os.makedirs(adir_full_path)

def save_context(context, app_path):
    """
    Saves a dictionary to a file in JSON format.
    """
    try:
        full_path = os.path.join(app_path, "results/results_json.txt")
        with open(full_path, 'w') as file:
            json.dump(context, file)
        print("[AIANALYZER] - Context has been saved to file.")
    except Exception as e:
        print(f"[AIANALYZER] - An error occurred while saving the context: {e}")


def read_context(checksum):
    """
    Reads a context from a JSON file.
    """
    try:
        full_path = "/home/mobsf/.MobSF/app_data/" + checksum + "/results/results_json.txt"
        with open(full_path, 'r') as file:
            context = json.load(file)
        print("Dictionary has been loaded from file.")
        return context
    except FileNotFoundError:
        print(f"No such file: {full_path}")
        return {'md5':checksum}
    except json.JSONDecodeError:
        print("Failed to decode JSON from file.")
        return {'md5':checksum}
    except Exception as e:
        print(f"An error occurred while reading the dictionary: {e}")
        return {'md5':checksum}