import zipfile
import subprocess
import os
import sys
import json


##################################################################################
# SUB FUNCTION: process an .apk file: unzip .apk, .dex to .jar, unzip .jar
##################################################################################
def process_apk(apk_path, dex2jar_path, is_windows, temp_dir):
    if is_windows is True:
        print('You are using a Windows System.')
        command_postfix = ".bat"
    else:
        print('You are using a UNIX System.')
        command_postfix = ".sh"

    print('Extracting ' + apk_path + '...')
    zip_ref = zipfile.ZipFile(apk_path, 'r')
    zip_ref.extractall(temp_dir)
    zip_ref.close()

    print('Searching for .dex files...')
    extracted_classes = []
    for path, subdirs, files in os.walk(r'' + temp_dir):
        for filename in files:
            f = os.path.join(path, filename)
            if f.endswith('.dex'):
                # use dex2jar for found dex files
                if dex2jar_path is None or dex2jar_path == '':
                    print('Using dex2jar on ' + f + '...')
                    subprocess.call(
                        ['d2j-dex2jar', '-f', f, '-o', f[0:-4] + '.jar'])
                else:
                    print('Using dex2jar on' + f + '...')
                    subprocess.call(
                        [dex2jar_path + 'd2j-dex2jar' + command_postfix, '-f', f, '-o', f[0:-4] + '.jar'])
                # unzip .jar files
                try:
                    print('Extracting ' + f[0:-4] + '.jar' + '...')
                    zip_ref = zipfile.ZipFile(f[0:-4] + '.jar', 'r')
                    zip_ref.extractall(f[0:-4])
                    print(f[0:-4] + '/')
                except FileNotFoundError:
                    print('error')
                finally:
                    extracted_classes.append(f[0:-4] + '/')
                    zip_ref.close()

    ##################################################################################
    # search unzipped .jar for tracker code signatures
    ##################################################################################
    print('Starting search for trackers.')
    tracker_data = []
    found_trackers = { 'trackers': {}, 'info': []}
    with open(os.path.dirname(__file__) + '/tracker.json', 'r') as tracker_file:
        tracker_data = json.load(tracker_file)

    # walk through all class directories generated from the .jar and list all files
    all_files = []
    is_react = False
    for extracted_class in extracted_classes:
        for path, subdirs, files in os.walk(r'' + extracted_class):
            for filename in files:
                f = os.path.join(path, filename)
                if is_windows is True:
                    f = f.replace('\\', '/')
                all_files.append(f)

    for tracker in tracker_data['trackers']:
        code_signature = tracker['code_signature']
        if code_signature == '' or code_signature == '.':
            continue
        else:
            # replace every '.' in code_signature with a '/'
            code_signature = code_signature.replace('.', '/')

            # make list of code signatures for same tracker, check each
            if ' | ' in code_signature:
                code_signature = code_signature.split(' | ')
            for file_path in all_files:
                # check if React (JavaScript) was used to develop app
                if 'com/facebook/react/' in file_path:
                    is_react = True
                if type(code_signature) is list:
                    for i in code_signature:
                        if i in file_path:
                            found_trackers['trackers'][tracker['name']] = {'website': tracker['website'],
                                                               'code_signature': tracker['code_signature'],
                                                               'network_signature': tracker['network_signature']}
                            break
                        else:
                            continue
                else:
                    if code_signature in file_path:
                        found_trackers['trackers'][tracker['name']] = {'website': tracker['website'],
                                                           'code_signature': tracker['code_signature'],
                                                           'network_signature': tracker['network_signature']}

    if is_react is True:
        info = 'App is using React (JavaScript), there is a high chance that we therefore have not been able to detect all trackers'
        found_trackers['info'].append(info)
        print('INFO: ' +info)
    return found_trackers


##################################################################################
# MAIN FUNCTION
##################################################################################
def dex2jar(workspace_dir, dex2jar_path, is_windows, temp_dir):
    print('Starting dex2jar script:')
    tracker_dictionary = {}
    # if single .apk file: call process_apk function
    if workspace_dir.endswith('.apk'):
        print('You chose a single .apk file.')
        tracker_dictionary[workspace_dir] = process_apk(apk_path=workspace_dir, dex2jar_path=dex2jar_path,
                                                                  is_windows=is_windows, temp_dir=temp_dir)

    # if directory with multiple .apk files
    else:
        print('You chose a directory.')
        all_files = []
        # ls workspace
        for path, subdirs, files in os.walk(r'' + workspace_dir):
            for filename in files:
                f = os.path.join(path, filename)
                all_files.append(str(f))

        for i in all_files:
            # find all .apk files
            if i.endswith('.apk'):
                tracker_dictionary[i] = process_apk(apk_path=i, dex2jar_path=dex2jar_path,
                                                              is_windows=is_windows, temp_dir=temp_dir)

    return tracker_dictionary
