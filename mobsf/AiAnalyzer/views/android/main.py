from pathlib import Path

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register
from mobsf.AiAnalyzer.views.android.helpers.sast_engine import prepare_semgrep_target_dirs, semgrep_scan
from mobsf.AiAnalyzer.views.android.file_scanner import ai_scan_secrets_files
from mobsf.AiAnalyzer.views.android.exp_comp_scanner import ai_scan_exported_components
from mobsf.AiAnalyzer.views.android.helpers.system_utils import create_app_data_folders, read_context, save_context
from mobsf.AiAnalyzer.views.android.rules_scanner import ai_scan_rules

from mobsf.MobSF.utils import (
    file_size,
    get_android_src_dir,
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import RecentScansDB
from mobsf.StaticAnalyzer.views.android.app import (
    get_app_name,
    parse_apk,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest,
    ai_manifest_data,
    extract_exp_components_xml,
)
from mobsf.StaticAnalyzer.views.common.shared_func import hash_gen, unzip

def ai_analyzer(request, checksum, api=False):
    template = 'ai_views/general.html'
    
    try:
        context = read_context(checksum)

        if not is_md5(checksum):
            return print_n_send_error_response(request, '[AIANALYZER] - Invalid Hash', api)
        robj = RecentScansDB.objects.filter(MD5=checksum)
        if not robj.exists():
            return print_n_send_error_response(request,'[AIANALYZER] - The file is not uploaded/available',api)
        typ = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        allowed_exts = ('.apk', '.ipa')
        allowed_typ = [i.replace('.', '') for i in allowed_exts]
        if (not filename.lower().endswith(allowed_exts) or typ not in allowed_typ):
            return print_n_send_error_response(request, '[AIANALYZER] - Invalid file extension or file type', api)

        context['dir'] = Path(settings.BASE_DIR)  # BASE DIR
        context['app_dir'] = Path(settings.UPLD_DIR) / checksum
        context['app_file'] = context['md5'] + '.apk'  # NEW FILENAME
        context['app_name'] = filename  # APP ORIGINAL NAME
        context['md5'] = checksum  # MD5
        context['app_path'] = (context['app_dir'] / context['app_file']).as_posix()
        context['size'] = str(file_size(context['app_path'])) + 'MB'  # FILE SIZE
        context['sha1'], context['sha256'] = hash_gen(context['app_path'])
        
        print('[AIANALYZER] - Scan Hash: ', checksum)

        
        return render(request, template, context)
    except Exception as e:
        print(e)
        context = {'title':'Error in main'}
        return render(request, template, context)

# Start the proces off AI analysis - TODO clean the function and only keep and create needed context.
def ai_analyzer_start(request, checksum, api=False):
    template = 'ai_views/general.html'

    context = {
        'title':'AI Analyzer Result',
        'version':'1',
        'md5':checksum
    }

    #========================PREPARE CONTEXT FOR OWASP AI ANALYSIS========================

    try:
        print('[AIANALYZER] - Preparing context for AI Analysis')
        # Input validation
        ai_app_dic = {}
        if not is_md5(checksum):
            return print_n_send_error_response(request, '[AIANALYYZER] - Invalid Hash', api)
        robj = RecentScansDB.objects.filter(MD5=checksum)
        if not robj.exists():
            return print_n_send_error_response(request,'[AIANALYZER] - The file is not uploaded/available',api)
        typ = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        allowed_exts = ('.apk', '.ipa')
        allowed_typ = [i.replace('.', '') for i in allowed_exts]
        if (not filename.lower().endswith(allowed_exts) or typ not in allowed_typ):
            return print_n_send_error_response(request, '[AIANALYZER] - Invalid file extension or file type', api)

        ai_app_dic['dir'] = Path(settings.BASE_DIR)  # BASE DIR
        ai_app_dic['app_name'] = filename  # APP ORIGINAL NAME
        ai_app_dic['md5'] = checksum  # MD5
        print('[AIANALYZER] - Scan Hash: ', checksum)
        # APP DIRECTORY
        ai_app_dic['app_dir'] = Path(settings.UPLD_DIR) / checksum
        ai_app_dic['tools_dir'] = ai_app_dic['dir'] / 'StaticAnalyzer' / 'tools'
        ai_app_dic['tools_dir'] = ai_app_dic['tools_dir'].as_posix()
        ai_app_dic['icon_path'] = ''
        ai_app_dic['app_data_dir'] =  '/home/mobsf/.MobSF/app_data/' + checksum + '/'
        create_app_data_folders(ai_app_dic['app_data_dir'])

    
        context['app_file'] = context['md5'] + '.apk'  # NEW FILENAME
        context['app_name'] = filename  # APP ORIGINAL NAME
        context['md5'] = checksum  # MD5
        context['app_path'] = (ai_app_dic['app_dir'] / context['app_file']).as_posix()
        context['size'] = str(file_size(context['app_path'])) + 'MB'  # FILE SIZE
        context['sha1'], context['sha256'] = hash_gen(context['app_path'])
        print('[AIANALYZER] - Starting Analysis on: ', ai_app_dic['app_name'])
        if typ == 'apk':
            ai_app_dic['app_file'] = ai_app_dic['md5'] + '.apk'  # NEW FILENAME
            ai_app_dic['app_path'] = (ai_app_dic['app_dir'] / ai_app_dic['app_file']).as_posix()
            ai_app_dic['app_dir'] = ai_app_dic['app_dir'].as_posix() + '/'
            ai_app_dic['files'] = unzip(ai_app_dic['app_path'], ai_app_dic['app_dir'])
            print('[AIANALYZER] - APK Extracted')
            if not ai_app_dic['files']:
                # Can't Analyze APK, bail out.
                return print_n_send_error_response(
                    request,
                    '[AIANALYZER] - APK file is invalid or corrupt',
                    api)
 
            # Manifest XML
            mani_file, ns, mani_xml = get_manifest(
                ai_app_dic['app_path'],
                ai_app_dic['app_dir'],
                ai_app_dic['tools_dir'],
                'apk',
            )
            ai_app_dic['manifest_file'] = mani_file
            ai_app_dic['parsed_xml'] = mani_xml
            # Parse APK with Androguard
            apk = parse_apk(ai_app_dic['app_path'])
            # get app_name
            ai_app_dic['real_name'] = get_app_name(
                apk,
                ai_app_dic['app_dir'],
                True,
            )
            
            # Test Exported Components
            # Get metadata for exported component extraction (used only for next step - extract_exp_components_xml)
            ai_man_data_dic = ai_manifest_data(ai_app_dic['parsed_xml'], ns)

            # extract exported components + their XML definitions
            act_cnt, pro_cnt, com_cnt, rcv_cnt, exp_components_manifest = extract_exp_components_xml(
                ai_app_dic['parsed_xml'],
                ns,
                ai_man_data_dic,
            )

            context['act_cnt'] = act_cnt
            context['pro_cnt'] = pro_cnt
            context['com_cnt'] = com_cnt
            context['rcv_cnt'] = rcv_cnt

            root = Path(settings.BASE_DIR) / 'AiAnalyzer'
            and_rules = root / 'views' / 'rules'
            code_vuln_rules = and_rules / 'android_rules_vuln.yaml'
            app_dir = Path(ai_app_dic['app_dir'])
            src = get_android_src_dir(app_dir, typ).as_posix() + '/'
            skip = {
                    'com/google', 'androidx/', 'okhttp2/', 'okhttp3/',
                    'com/android', 'com/squareup', 'okhttp/'
                    'android/content', 'com/twitter', 'twitter4j/',
                    'android/support', 'org/apache', 'oauth/signpost',
                    'android/arch', 'org/chromium', 'com/facebook',
                    'org/spongycastle', 'org/bouncycastle',
                    'com/amazon/identity', 'io/fabric/sdk',
                    'com/instabug', 'com/crashlytics/android',
                    'kotlinx/', 'kotlin/', 'com/bumptech', 'org/intellij', 
                    'org/jetbrains', 'com/braze', 'io/sentry', 'com/adjust'
            }

            print("")
            print('[AIANALYZER] - SEMGREP CODE ANALYSIS STARTED')
            
            # Code Analysis
            semgrep_target_dirs = prepare_semgrep_target_dirs(src, skip)
            #print(semgrep_target_dirs)
            code_findings = semgrep_scan(
                code_vuln_rules.as_posix(),
                semgrep_target_dirs
                )
            
            print('[AIANALYZER] - SEMGREP CODE ANALYSIS FINISHED')
            #========================START THE AI ANALYSIS========================
            #collect results of all scans 
            results = {}
            #======================== FILESYSTEM SCAN = source+log+sandbox ========================
            print('==============================================================================================================')
            print('[AIANALYZER] - FILE SECRET AI ANALYSIS STARTED')
            # scan_secrets_log_file()
            # scan_secrets_filesystem()
            # scan_secrets_sourcecode()
            results['filesystem_scan'] = ai_scan_secrets_files(checksum)
            print('[AIANALYZER] - FILE SECRET AI ANALYSIS FINISHED')
            #======================== Exported components scan = source code + manifest ========================
            print('==============================================================================================================')
            print('[AIANALYZER] - EXPORTED COMPONENTS AI ANALYSIS STARTED')
            # scan_exp_components()
            results['exp_component_scan'] = ai_scan_exported_components(ai_app_dic, checksum, exp_components_manifest)
            print('[AIANALYZER] - EXPORTED COMPONENTS AI ANALYSIS FINISHED')
            #======================== Semgrep vulnerability scan = source code + manifest ========================
            print('==============================================================================================================')
            print('[AIANALYZER] - RULES SCAN AI ANALYSIS STARTED') 
            print('testing ' + str(len(code_findings)) + ' findings')
            # scan_logs_code()
            # scan_vuln_code()
            results['rules_scan'] = ai_scan_rules(code_findings)
            print('[AIANALYZER] - RULES SCAN AI ANALYSIS FINISHED')

            context['findings'] = results['exp_component_scan']
            context['raw_log'] = results['filesystem_scan']['raw_log_scan_result']
            context['filesystem'] = results['filesystem_scan']['fs_secrets_scan_results']
            context['rules_log'] = results['rules_scan']['logs']
            context['rules_vuln'] = results['rules_scan']['vuln']

            save_context(context, ai_app_dic['app_data_dir'])
        else:
            err = ('[AIANALYZER] - Only APK Android Source code supported now!')
            print.error(err)
    except Exception as excep:
        print('[AIANALYZER] - Error Performing AI Analysis')
        msg = str(excep)
        print(msg)
        exp = excep.__doc__
        return print_n_send_error_response(request, msg, api, exp)

    return render(request, template, context)
