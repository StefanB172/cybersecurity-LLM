from mobsf.AiAnalyzer.views.android.helpers.source_code import read_java_file
from mobsf.AiAnalyzer.views.prompts.exp_comp_lang_chains import scan_exp_components
import time

def ai_scan_exported_components(ai_app_dic, app_md5, exp_components_manifest):
    try:
        #======================== M4 - EXPORTED COMPONENTS ========================
        # Get a code snipets of each component onCreate + onReceive methods
        # For each component in list + his code = call test_exported_component()
        results = {}
        for type in exp_components_manifest.keys():
            for component in exp_components_manifest[type]:
                #time.sleep(15)
                tmp = component.replace('.', '/')
                print('currently testing: ' + tmp)
                path_to_file = ai_app_dic['app_dir'] + 'java_source/' + tmp + '.java'
                java_code = read_java_file(path_to_file)
                #component_code = parse_java_file(java_code)

                component_definition = exp_components_manifest[type][component]
                #LangChain testing
                results[component] = scan_exp_components(component_definition, java_code)

        #======================== M4 - USER INPUTS ========================
        #======================== M4 - NETWORK     ========================
        return results
    except:
        print.exception('[AIANALYZER] - Error Performing M4 AI Analysis')

    return 1