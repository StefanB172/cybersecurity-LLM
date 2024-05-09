import os
import subprocess
import json
from pathlib import Path
from mobsf.AiAnalyzer.views.android.models.semgrep_finding import AnalysisResult
import semgrep


def semgrep_scan(rules_yaml_file, target_dirs):
    try:    
        # Join the list of directories into a string separated by spaces
        directories_str = " ".join(target_dirs)
       
        # Construct the Semgrep command
        semgrep_command = f"/usr/local/bin/semgrep --config={rules_yaml_file} --json {directories_str}"
        
        # Execute the command
        result = subprocess.run(semgrep_command, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            print("Semgrep error:", result.stderr)
            return

        # Parse JSON output
        findings_json = json.loads(result.stdout)

        # Extract and return only the "results" field
        findings_str_list = findings_json['results']
        all_findings_obj_list = [AnalysisResult(json_data) for json_data in findings_str_list]
        filtered_findings = remove_duplicate_findings(all_findings_obj_list)
        return filtered_findings
    
    except json.JSONDecodeError as e:
        print("[AIANALYZER] - SEMGREP ERROR - SAST-ENGINE - ERROR PARSING RESULT JSON")
        print(e)
        return []
    except Exception as excep:
        print("[AIANALYZER] - SEMGREP ERROR - SAST-ENGINE")
        print(excep)
        return []

def remove_duplicate_findings(all_findings_obj_list):
    filtered_findings = []
    appended_masks = []
    for finding in all_findings_obj_list:
        mask = (finding.check_id, finding.path)
        if mask not in appended_masks:
            filtered_findings.append(finding)
            appended_masks.append(mask)
    return filtered_findings

def prepare_semgrep_target_dirs(source_code_directory, paths_to_skip):
    try:
        # Initialize a list to store first level directory paths
        first_level_directories = []
        for item in os.listdir(source_code_directory):
            full_path = os.path.join(source_code_directory, item)
            if os.path.isdir(full_path):
                first_level_directories.append(full_path)

        directories_to_scan = set()

        for dir in first_level_directories:
            for dir2 in os.listdir(dir):
                full_path = os.path.join(dir, dir2)
                if os.path.isdir(full_path):
                    if any(skp in str(full_path) for skp in paths_to_skip):
                        continue  # Skip this path
                    directories_to_scan.add(full_path)
        if len(directories_to_scan) == 0:
            directories_to_scan.add(source_code_directory)
    except Exception as e:
        print(e)
    return directories_to_scan
