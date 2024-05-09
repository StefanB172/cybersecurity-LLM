# -*- coding: utf_8 -*-
"""Android manifest analysis utils."""
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from xml.dom import minidom
from xml.parsers.expat import ExpatError

from bs4 import BeautifulSoup

from django.conf import settings

from mobsf.MobSF.utils import (
    find_java_binary,
    is_file_exists,
)

from mobsf.StaticAnalyzer.views.android.manifest_analysis import get_browsable_activities

# pylint: disable=E0401
from .dvm_permissions import DVM_PERMISSIONS

logger = logging.getLogger(__name__)


ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'


def get_manifest_file(app_dir, app_path, tools_dir, typ):
    """Read the manifest file."""
    try:
        manifest = ''
        if typ == 'aar':
            logger.info('Getting AndroidManifest.xml from AAR')
            manifest = os.path.join(app_dir, ANDROID_MANIFEST_FILE)
        elif typ == 'apk':
            logger.info('Getting AndroidManifest.xml from APK')
            manifest = get_manifest_apk(app_path, app_dir, tools_dir)
        else:
            logger.info('Getting AndroidManifest.xml from Source Code')
            if typ == 'eclipse':
                manifest = os.path.join(app_dir, ANDROID_MANIFEST_FILE)
            elif typ == 'studio':
                manifest = os.path.join(
                    app_dir,
                    f'app/src/main/{ANDROID_MANIFEST_FILE}')
        return manifest
    except Exception:
        logger.exception('Getting AndroidManifest.xml file')


def get_manifest_apk(app_path, app_dir, tools_dir):
    """Get readable AndroidManifest.xml.

    Should be called before get_icon_apk() function
    """
    try:
        manifest = None
        if (len(settings.APKTOOL_BINARY) > 0
                and is_file_exists(settings.APKTOOL_BINARY)):
            apktool_path = settings.APKTOOL_BINARY
        else:
            apktool_path = os.path.join(tools_dir, 'apktool_2.9.1.jar')
        output_dir = os.path.join(app_dir, 'apktool_out')
        args = [find_java_binary(),
                '-jar',
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                apktool_path,
                '--match-original',
                '--frame-path',
                tempfile.gettempdir(),
                '-f', '-s', 'd',
                app_path,
                '-o',
                output_dir]
        manifest = os.path.join(output_dir, ANDROID_MANIFEST_FILE)
        if is_file_exists(manifest):
            # APKTool already created readable XML
            return manifest
        logger.info('Converting AXML to XML')
        subprocess.check_output(args)  # User input is MD5 and validated
    except Exception:
        logger.exception('Getting Manifest file')
    return manifest


def get_xml_namespace(xml_str):
    """Get namespace."""
    m = re.search(r'manifest (.{1,250}?):', xml_str)
    if m:
        return m.group(1)
    logger.warning('XML namespace not found')
    return None


def get_fallback():
    logger.warning('Using Fake XML to continue the Analysis')
    return minidom.parseString(
        (r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android='
         r'"http://schemas.android.com/apk/res/android" '
         r'android:versionCode="Failed"  '
         r'android:versionName="Failed" package="Failed"  '
         r'platformBuildVersionCode="Failed" '
         r'platformBuildVersionName="Failed XML Parsing" ></manifest>'))


def bs4_xml_parser(xml_str):
    """Attempt to parse XML with bs4."""
    logger.info('Parsing AndroidManifest.xml with bs4')
    try:
        soup = BeautifulSoup(xml_str, 'xml')
        return soup.prettify().encode('utf-8', 'ignore')
    except Exception:
        logger.exception('Parsing XML with bs4')
    return None


def get_manifest(app_path, app_dir, tools_dir, typ):
    """Get the manifest file."""
    try:
        ns = 'android'
        manifest_file = get_manifest_file(
            app_dir,
            app_path,
            tools_dir,
            typ)
        mfile = Path(manifest_file)
        if not mfile.exists():
            logger.warning('apktool failed to extract '
                           'AndroidManifest.xml')
            return manifest_file, ns, get_fallback()
        logger.info('Parsing AndroidManifest.xml')
        xml_str = mfile.read_text('utf-8', 'ignore')
        ns = get_xml_namespace(xml_str)
        if ns and ns == 'xmlns':
            ns = 'android'
        if ns and ns != 'android':
            logger.warning('Non standard XML namespace: %s', ns)
        try:
            return manifest_file, ns, minidom.parseString(xml_str)
        except ExpatError:
            logger.warning('Parsing AndroidManifest.xml failed')
            return manifest_file, ns, minidom.parseString(
                bs4_xml_parser(xml_str))
    except Exception:
        logger.exception('Parsing Error')
    return manifest_file, ns, get_fallback()


def manifest_data(mfxml, ns):
    """Extract manifest data."""
    try:
        logger.info('Extracting Manifest Data')
        svc = []
        act = []
        brd = []
        cnp = []
        lib = []
        perm = []
        cat = []
        icons = []
        dvm_perm = {}
        package = ''
        minsdk = ''
        maxsdk = ''
        targetsdk = ''
        mainact = ''
        androidversioncode = ''
        androidversionname = ''
        applications = mfxml.getElementsByTagName('application')
        permissions = mfxml.getElementsByTagName('uses-permission')
        permsdk23 = mfxml.getElementsByTagName('uses-permission-sdk-23')
        if permsdk23:
            permissions.extend(permsdk23)
        manifest = mfxml.getElementsByTagName('manifest')
        activities = mfxml.getElementsByTagName('activity')
        services = mfxml.getElementsByTagName('service')
        providers = mfxml.getElementsByTagName('provider')
        receivers = mfxml.getElementsByTagName('receiver')
        libs = mfxml.getElementsByTagName('uses-library')
        sdk = mfxml.getElementsByTagName('uses-sdk')
        categories = mfxml.getElementsByTagName('category')
        for node in sdk:
            minsdk = node.getAttribute(f'{ns}:minSdkVersion')
            maxsdk = node.getAttribute(f'{ns}:maxSdkVersion')
            # Esteve 08.08.2016 - begin - If android:targetSdkVersion
            # is not set, the default value is the one of the
            # minSdkVersiontargetsdk
            # = node.getAttribute (f'{ns}:targetSdkVersion')
            if node.getAttribute(f'{ns}:targetSdkVersion'):
                targetsdk = node.getAttribute(f'{ns}:targetSdkVersion')
            else:
                targetsdk = node.getAttribute(f'{ns}:minSdkVersion')
            # End
        for node in manifest:
            package = node.getAttribute('package')
            androidversioncode = node.getAttribute(f'{ns}:versionCode')
            androidversionname = node.getAttribute(f'{ns}:versionName')
        alt_main = ''
        for activity in activities:
            act_2 = activity.getAttribute(f'{ns}:name')
            act.append(act_2)
            if not mainact:
                # ^ Some manifest has more than one MAIN, take only
                # the first occurrence.
                for sitem in activity.getElementsByTagName('action'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.action.MAIN':
                        mainact = activity.getAttribute(f'{ns}:name')
                # Manifest has no MAIN, look for launch activity.
                for sitem in activity.getElementsByTagName('category'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.category.LAUNCHER':
                        alt_main = activity.getAttribute(f'{ns}:name')
        if not mainact and alt_main:
            mainact = alt_main

        for service in services:
            service_name = service.getAttribute(f'{ns}:name')
            svc.append(service_name)

        for provider in providers:
            provider_name = provider.getAttribute(f'{ns}:name')
            cnp.append(provider_name)

        for receiver in receivers:
            rec = receiver.getAttribute(f'{ns}:name')
            brd.append(rec)

        for _lib in libs:
            library = _lib.getAttribute(f'{ns}:name')
            lib.append(library)

        for category in categories:
            cat.append(category.getAttribute(f'{ns}:name'))

        for application in applications:
            try:
                icon_path = application.getAttribute(f'{ns}:icon')
                icons.append(icon_path)
            except Exception:
                continue  # No icon attribute?

        android_permission_tags = ('com.google.', 'android.', 'com.google.')
        for permission in permissions:
            perm.append(permission.getAttribute(f'{ns}:name'))
        for full_perm in perm:
            # For general android permissions
            prm = full_perm
            pos = full_perm.rfind('.')
            if pos != -1:
                prm = full_perm[pos + 1:]
            if not full_perm.startswith(android_permission_tags):
                prm = full_perm
            try:
                dvm_perm[full_perm] = DVM_PERMISSIONS[
                    'MANIFEST_PERMISSION'][prm]
            except KeyError:
                # Handle Special Perms
                if DVM_PERMISSIONS['SPECIAL_PERMISSIONS'].get(full_perm):
                    dvm_perm[full_perm] = DVM_PERMISSIONS[
                        'SPECIAL_PERMISSIONS'][full_perm]
                else:
                    dvm_perm[full_perm] = [
                        'unknown',
                        'Unknown permission',
                        'Unknown permission from android reference',
                    ]

        man_data_dic = {
            'services': svc,
            'activities': act,
            'receivers': brd,
            'providers': cnp,
            'libraries': lib,
            'categories': cat,
            'perm': dvm_perm,
            'packagename': package,
            'mainactivity': mainact,
            'min_sdk': minsdk,
            'max_sdk': maxsdk,
            'target_sdk': targetsdk,
            'androver': androidversioncode,
            'androvername': androidversionname,
            'icons': icons,
        }

        return man_data_dic
    except Exception:
        logger.exception('Extracting Manifest Data')

# vracia manifest data pre ziskanie exported components v dalsej funkcii
def ai_manifest_data(mfxml, ns):
    """Extract manifest data for AI context."""
    try:
        print('[AIANALYZER] - Extracting Manifest Data for component code extraction')
        minsdk = ''
        targetsdk = ''
        mainact = ''
        activities = mfxml.getElementsByTagName('activity')
        sdk = mfxml.getElementsByTagName('uses-sdk')
        
        for node in sdk:
            minsdk = node.getAttribute(f'{ns}:minSdkVersion')
            # Esteve 08.08.2016 - begin - If android:targetSdkVersion
            # is not set, the default value is the one of the
            # minSdkVersiontargetsdk
            # = node.getAttribute (f'{ns}:targetSdkVersion')
            if node.getAttribute(f'{ns}:targetSdkVersion'):
                targetsdk = node.getAttribute(f'{ns}:targetSdkVersion')
            else:
                targetsdk = node.getAttribute(f'{ns}:minSdkVersion')
            # End

        alt_main = ''
        for activity in activities:
            if not mainact:
                # ^ Some manifest has more than one MAIN, take only
                # the first occurrence.
                for sitem in activity.getElementsByTagName('action'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.action.MAIN':
                        mainact = activity.getAttribute(f'{ns}:name')
                # Manifest has no MAIN, look for launch activity.
                for sitem in activity.getElementsByTagName('category'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.category.LAUNCHER':
                        alt_main = activity.getAttribute(f'{ns}:name')

        if not mainact and alt_main:
            mainact = alt_main

        man_data_dic = {
            'mainactivity': mainact,
            'min_sdk': minsdk,
            'target_sdk': targetsdk,
        }

        return man_data_dic
    except Exception:
        logger.exception('[AIANALYZER] - Error in Extracting Manifest Data for component code extraction')

# ziskaj exportovane komponenty a ich kod
def extract_exp_components_xml(mfxml, ns, man_data_dic):
    applications = mfxml.getElementsByTagName('application')
    permissions = mfxml.getElementsByTagName('permission')
    permission_dict = {}
    exp_count = dict.fromkeys(['act', 'ser', 'bro', 'cnt'], 0)
    exported = {
        'exp_activity':[],
        'exp_provider':[],
        'exp_service':[],
        'exp_receiver':[],
    }
    browsable_activities = {}

    try:
        # PERMISSION
        for permission in permissions:
            if permission.getAttribute(f'{ns}:protectionLevel'):
                protectionlevel = permission.getAttribute(
                    f'{ns}:protectionLevel')
                if protectionlevel == '0x00000000':
                    protectionlevel = 'normal'
                elif protectionlevel == '0x00000001':
                    protectionlevel = 'dangerous'
                elif protectionlevel == '0x00000002':
                    protectionlevel = 'signature'
                elif protectionlevel == '0x00000003':
                    protectionlevel = 'signatureOrSystem'

                permission_dict[permission.getAttribute(f'{ns}:name')] = protectionlevel
            elif permission.getAttribute(f'{ns}:name'):
                permission_dict[permission.getAttribute(f'{ns}:name')] = 'normal'
                
        for application in applications:
            if application.getAttribute(f'{ns}:permission'):
                perm_appl_level_exists = True
                perm_appl_level = application.getAttribute(
                    f'{ns}:permission')
            else:
                perm_appl_level_exists = False

            for node in application.childNodes:
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = 'act'
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(f'{ns}:name')] = browse_dic
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = 'act'
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(f'{ns}:name')] = browse_dic
                elif node.nodeName == 'provider':
                    itemname = 'Content Provider'
                    cnt_id = 'cnt'
                elif node.nodeName == 'receiver':
                    itemname = 'Broadcast Receiver'
                    cnt_id = 'bro'
                elif node.nodeName == 'service':
                    itemname = 'Service'
                    cnt_id = 'ser'
                else:
                    itemname = 'NIL'

                # Exported Check
                item = ''
                is_inf = False
                is_perm_exist = False
                # Esteve 23.07.2016 - begin - initialise variables to identify
                # the existence of a permission at the component level that
                # matches a permission at the manifest level
                prot_level_exist = False
                protlevel = ''
                # End
                if itemname != 'NIL':
                    if node.getAttribute(f'{ns}:exported') == 'true':
                        item = node.getAttribute(f'{ns}:name')
                        if node.getAttribute(f'{ns}:permission'):
                            # permission exists
                            is_perm_exist = True
                        if is_perm_exist:
                            if node.getAttribute(f'{ns}:permission') in permission_dict:
                                # Esteve 23.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                # included in the EXPORTED data structure for further treatment; components in this situation are also
                                # counted as exported.
                                prot_level_exist = True
                                protlevel = permission_dict[
                                    node.getAttribute(f'{ns}:permission')]
                            if prot_level_exist:
                                if protlevel == 'normal':
                                    sort_exported(exported, item, itemname)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                elif protlevel == 'dangerous':
                                    sort_exported(exported, item, itemname)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                            else:
                                sort_exported(exported, item, itemname)
                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                            # Esteve 23.07.2016 - end
                        else:
                            # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                            # application level. As they are exported, they
                            # are not protected.
                            if perm_appl_level_exists is False:
                                sort_exported(exported, item, itemname)
                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                            # Esteve 24.07.2016 - end
                            # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                            #  level. Two options are possible:
                            #        1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                            #           we did just above for permissions specified at the component level.
                            #        2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                            # defined in the analysed application.
                            else:
                                if perm_appl_level in permission_dict:
                                    prot_level_exist = True
                                    protlevel = permission_dict[
                                        perm_appl_level]
                                if prot_level_exist:
                                    if protlevel == 'normal':
                                        sort_exported(exported, item, itemname)
                                        exp_count[cnt_id] = exp_count[cnt_id] + 1
                                    elif protlevel == 'dangerous':
                                        sort_exported(exported, item, itemname)
                                        exp_count[cnt_id] = exp_count[cnt_id] + 1
                                else:
                                    sort_exported(exported, item, itemname)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                            # Esteve 24.07.2016 - end
                    elif node.getAttribute(f'{ns}:exported') != 'false':
                        # Check for Implicitly Exported
                        # Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == 'intent-filter':
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute(f'{ns}:name')
                            if node.getAttribute(f'{ns}:permission'):
                                # permission exists
                                is_perm_exist = True
                            if is_perm_exist:
                                if node.getAttribute(f'{ns}:permission') in permission_dict:
                                    # Esteve 24.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                    # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                    # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                    #  included in the EXPORTED data structure for further treatment; components in this situation are also
                                    #  counted as exported.
                                    prot_level_exist = True
                                    protlevel = permission_dict[node.getAttribute(f'{ns}:permission')]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1        
                                else:
                                    sort_exported(exported, item, itemname)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                            else:
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                # application level. As they are exported,
                                # they are not protected.
                                if perm_appl_level_exists is False:
                                    sort_exported(exported, item, itemname)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 24.07.2016 - end
                                    
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                # level. Two options are possible:
                                # 1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                #  we did just above for permissions specified at the component level.
                                # 2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                #  defined in the analysed application.
                                else:
                                    if perm_appl_level in permission_dict:
                                        prot_level_exist = True
                                        protlevel = permission_dict[perm_appl_level]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1   
                                    else:
                                        sort_exported(exported, item, itemname)
                                        exp_count[cnt_id] = exp_count[ cnt_id] + 1
                                # Esteve 24.07.2016 - end
                                        
                                # Esteve 29.07.2016 - begin The component is not explicitly exported (android:exported is not 'true'). It is not implicitly exported either (it does not
                                # make use of an intent filter). Despite that, it could still be exported by default, if it is a content provider and the android:targetSdkVersion
                                # is older than 17 (Jelly Bean, Android version 4.2). This is true regardless of the system's API level.
                                # Finally, it must also be taken into account that, if the minSdkVersion is greater or equal than 17, this check is unnecessary, because the
                                # app will not be run on a system where the
                                # system's API level is below 17.
                        else:
                            if man_data_dic['min_sdk'] and man_data_dic['target_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_4_2_LEVEL:
                                if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) < ANDROID_4_2_LEVEL:
                                    item = node.getAttribute(f'{ns}:name')
                                    if node.getAttribute(f'{ns}:permission'):
                                        # permission exists
                                        is_perm_exist = True
                                    if is_perm_exist:
                                        if node.getAttribute(f'{ns}:permission') in permission_dict:
                                            prot_level_exist = True
                                            protlevel = permission_dict[node.getAttribute(f'{ns}:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                sort_exported(exported, item, itemname)
                                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                sort_exported(exported, item, itemname)
                                                exp_count[cnt_id] = exp_count[cnt_id] + 1  
                                        else:
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1
                                    else:
                                        if perm_appl_level_exists is False:
                                            sort_exported(exported, item, itemname)
                                            exp_count[cnt_id] = exp_count[cnt_id] + 1
                                        else:
                                            if perm_appl_level in permission_dict:
                                                prot_level_exist = True
                                                protlevel = permission_dict[perm_appl_level]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    sort_exported(exported, item, itemname)
                                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                                elif protlevel == 'dangerous':
                                                    sort_exported(exported, item, itemname)
                                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                            else:
                                                sort_exported(exported, item, itemname)
                                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                                    # Esteve 29.07.2016 - end
                                                
                                    # Esteve 08.08.2016 - begin - If the content provider does not target an API version lower than 17, it could still be exported by default, depending
                                    # on the API version of the platform. If it was below 17, the content
                                    # provider would be exported by default.
                                else:
                                    if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) >= 17:
                                        item = node.getAttribute(f'{ns}:name')
                                        if node.getAttribute(f'{ns}:permission'):
                                            # permission exists
                                            is_perm_exist = True
                                        if is_perm_exist:
                                            if node.getAttribute(f'{ns}:permission') in permission_dict:
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    node.getAttribute(f'{ns}:permission')]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    sort_exported(exported, item, itemname)
                                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                                if protlevel == 'dangerous':
                                                    sort_exported(exported, item, itemname)
                                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                            else:
                                                sort_exported(exported, item, itemname)
                                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                                        else:
                                            if perm_appl_level_exists is False:
                                                sort_exported(exported, item, itemname)
                                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                                            else:
                                                if perm_appl_level in permission_dict:
                                                    prot_level_exist = True
                                                    protlevel = permission_dict[perm_appl_level]
                                                if prot_level_exist:
                                                    if protlevel == 'normal':
                                                        sort_exported(exported, item, itemname)
                                                        exp_count[cnt_id] = exp_count[cnt_id] + 1
                                                    elif protlevel == 'dangerous':
                                                        sort_exported(exported, item, itemname)
                                                        exp_count[cnt_id] = exp_count[cnt_id] + 1
                                                else:
                                                    sort_exported(exported, item, itemname)
                                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                    # Esteve 08.08.2016 - end
                                                    
        # At this point we have all exported components, now we need to get their xml definition                                            
        print('[AIANALYZER] - Extracting Manifest Data for exported components')
        
        result = {
            'activity':{},
            'provider':{},
            'receiver':{},
            'service':{}
        }

        activities = mfxml.getElementsByTagName('activity')
        services = mfxml.getElementsByTagName('service')
        providers = mfxml.getElementsByTagName('provider')
        receivers = mfxml.getElementsByTagName('receiver')

        component_dic = {}
        act_cnt = 0
        for activity in activities:
            act_name = activity.getAttribute(f'{ns}:name')
            if act_name in exported['exp_activity']:
                component_dic[act_name] = activity.toxml()
                act_cnt += 1
        result['activity'] = component_dic

        component_dic = {}
        pro_cnt = 0
        for provider in providers:
            prv_name = provider.getAttribute(f'{ns}:name')
            if prv_name in exported['exp_provider']:
                component_dic[prv_name] = provider.toxml()
                pro_cnt += 1
        result['provider'] = component_dic

        component_dic = {}
        com_cnt = 0
        for service in services:
            srv_name = service.getAttribute(f'{ns}:name')
            if srv_name in exported['exp_service']:
                component_dic[srv_name] = service.toxml()
                com_cnt += 1
        result['service'] = component_dic

        component_dic = {}
        rcv_cnt = 0
        for receiver in receivers:
            rcv_name = receiver.getAttribute(f'{ns}:name')
            if rcv_name in exported['exp_receiver']:
                component_dic[rcv_name] = receiver.toxml()
                rcv_cnt += 1
        result['receiver'] = component_dic

        return act_cnt, pro_cnt, com_cnt, rcv_cnt, result
    except Exception:
        logger.exception('[AIANALYZER] - ERROR IN - Performing Manifest Analysis')


def sort_exported(exported, item, itemname):
    if itemname == 'Activity':
        exported['exp_activity'].append(item)
    elif itemname == 'Activity-Alias':
        exported['exp_activity'].append(item)
    elif itemname == 'Content Provider':
        exported['exp_provider'].append(item)
    elif itemname == 'Broadcast Receiver':
        exported['exp_receiver'].append(item)
    elif itemname == 'Service':
        exported['exp_service'].append(item)
    else:
        print('[AIANALYZER] - ERROR IN manifest_util.py - sort_exported() not parsed correctly')
    return exported