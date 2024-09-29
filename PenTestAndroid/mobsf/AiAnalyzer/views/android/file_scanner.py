import os
from pathlib import Path
from mobsf.AiAnalyzer.views.android.helpers.string_processing import parse_raw_strings
from mobsf.AiAnalyzer.views.android.helpers.system_utils import extract_file_data
from mobsf.AiAnalyzer.views.prompts.files_lang_chains import Secrets, scan_secrets_filesystem, scan_secrets_log_file




def ai_scan_secrets_files(md5):
    results = {}
    try:
        app_data_dir = '/home/mobsf/.MobSF/app_data/' + md5 + '/'
        #======================== M1 - LOGS ========================
        print('[AIANALYZER] - ANALYZING LOG FILES')
        input_log_file_path = app_data_dir + 'logs/log_raw.txt'
        output_log_file_path = app_data_dir + 'logs/log_processed.txt'
        file_path = Path(input_log_file_path)
        if file_path.exists():
            parse_raw_strings(input_log_file_path, output_log_file_path, is_log_file=1)
            raw_log_scan_result = scan_secrets_log_file(output_log_file_path)
            results['raw_log_scan_result'] = raw_log_scan_result
        else:
            print("Log file was not uploaded. Not found - " + str(file_path))
            results['raw_log_scan_result'] = "Log file was not uploaded. Not found - " + str(file_path)
        #======================== M1 - SOURCE CODE - HARCODED ========================
        print('[AIANALYZER] - ANALYZING SOURCE CODE FILES')
        # check z trufflehogu
        #======================== M1 - FILE SYSTEM ========================
        print('[AIANALYZER] - ANALYZING APP FILESYSTEM FILES')
        internal_storage_dir_path = app_data_dir + 'filesystem/internal/'
        external_storage_dir_path = app_data_dir + 'filesystem/external/'
        # Iterate over all files in the INTERNAL directory
        internal_storage = {}
        
        for root, dirs, files in os.walk(internal_storage_dir_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # Check if it's a regular file (not a directory or a link)
                if os.path.isfile(file_path):
                    # Skip the file if its size is 0 (it's empty)
                    if os.path.getsize(file_path) > 0:
                        internal_storage[file_name] = extract_file_data(file_path, min_length=10)
                    else:
                        continue  # Skip empty files

        # Iterate over all files in the EXTERANL directory
        external_storage = {}

        for root, dirs, files in os.walk(external_storage_dir_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # Check if it's a regular file (not a directory or a link)
                if os.path.isfile(file_path):
                    # Skip the file if its size is 0 (it's empty)
                    if os.path.getsize(file_path) > 0:
                        external_storage[file_name] = extract_file_data(file_path, min_length=10)
                    else:
                        continue  # Skip empty files

        fs_scan_result = {}
        for file_name in internal_storage.keys():
            print("currently testing: " + str(file_name))
            fs_secrets_scan = scan_secrets_filesystem(internal_storage[file_name])
            if not are_all_secrets_lists_empty(fs_secrets_scan):
                fs_scan_result[file_name] = fs_secrets_scan
        
        for file_name in external_storage.keys():
            print("currently testing: " + str(file_name))
            fs_secrets_scan = scan_secrets_filesystem(external_storage[file_name])
            if not are_all_secrets_lists_empty(fs_secrets_scan):
                fs_scan_result[file_name] = fs_secrets_scan

        results['fs_secrets_scan_results'] = fs_scan_result
        return results
    except Exception as e:
        err = ('[AIANALYZER] - Error Performing M1 AI Analysis')
        print(e)
        return None
    return results


# Function to check if all lists in the given Secrets class instance are empty
def are_all_secrets_lists_empty(secrets_dict) -> bool:
    for list in secrets_dict.values():
            if len(list) > 0:
                return False
    return True