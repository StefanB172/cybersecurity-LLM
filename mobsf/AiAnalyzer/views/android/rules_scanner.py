from mobsf.AiAnalyzer.views.android.helpers.source_code import read_java_file
from mobsf.AiAnalyzer.views.prompts.rules_lang_chain import scan_logs_code, scan_vuln_code
import time

def ai_scan_rules(code_findings):
    try:
        results = {}
        results['logs'] = []
        results['vuln'] = []
        scanned_paths_log = []
        all_findings = len(code_findings)
        current_finding = 1
        for finding in code_findings:
            #time.sleep(25)
            #Scan for sensitive data being logged
            print("testing finding " + str(current_finding) + '/' + str(all_findings) + ' ' + str(finding.extra.metadata.llmchain))
            current_finding += 1
            if finding.extra.metadata.llmchain == "logs":
                if finding.path not in scanned_paths_log:
                    file_content = read_java_file(finding.path)
                    # tu sa oplati len model gpt-4
                    log_scan = scan_logs_code(file_content, finding.path)
                    if "aaa" in log_scan['logged_secrets'].lower():
                        continue
                    results['logs'].append(log_scan)
                    scanned_paths_log.append(finding.path)
            #scan suspicious functions for vulnerabilities
            elif finding.extra.metadata.llmchain == "vuln":
                file_content = read_java_file(finding.path)
                print('filesize to scan = ' + str(len(file_content)))
                vuln_scan = scan_vuln_code(finding, file_content, finding.path)
                #if vuln_scan['vulnerable']:
                results['vuln'].append(vuln_scan)
        return results
    except Exception as e:
        print(e)
        return 0
    