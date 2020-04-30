import argparse
import csv
import os
import shutil
import subprocess
import webbrowser
from helper import *
from subtasks import CodeSignature, GenerateOutput, PermissionAnalyser

script_directory = digest_path(os.path.dirname(os.path.realpath(__file__)).replace('\\','/'))  # path of this script
temp_dir = script_directory + 'temp/'  # path to general temporary files
ghidra_project = temp_dir + 'ghidra-project/'  # path to temporary ghidra project
windows = True if os.name == 'nt' else False  # true if running on windows

# input
apk = None  # path to apk file or folder with apks
ghidra = None  # path to ghidra
dex2jar = None  # path to dex2jar tool
apktool = None  # path to apk tool
output = None  # destination folder
deep = False  # deep search in ghidra

# output
result = {}


def init():
    parser = argparse.ArgumentParser(description='Generic Exodus: Analyse APKs')
    parser.add_argument('-a', '--apk', help='path to apk file', required=True)
    parser.add_argument('-g', '--ghidra', help='path to ghidra application folder', required=True)
    parser.add_argument('-t', '--apktool', help='path to apktool application folder', required=False)
    parser.add_argument('-d', '--dex2jar', help='path to dex2jar application folder', required=False)
    parser.add_argument('-o', '--output', help='path to output folder', required=False)
    parser.add_argument('-f', '--force-deep-search', action='store_true')
    args = vars(parser.parse_args())
    run(args)


def run(args):
    global apk, deep, ghidra, apktool, dex2jar, output

    apk = digest_path(args['apk'], False)
    if os.path.isdir(apk):
        apk = apk + '/'
    ghidra = digest_path(args['ghidra'])
    apktool = None if args['apktool'] is None else digest_path(args['apktool'])
    dex2jar = None if args['dex2jar'] is None else digest_path(args['dex2jar'])
    deep = args['force_deep_search']

    # check output and create folder if necessary
    if args['output'] is not None:
        output = digest_path(args['output'])
    else:
        output = script_directory + 'output/'
    if not os.path.exists(output):
        os.makedirs(output)

    print('\n### init ###\n')
    print('[script directory] ' + script_directory)
    print('[apk] ' + apk)
    print('[ghidra] ' + ghidra)
    print('[apktool] ' + ('(not specified)' if apktool is None else apktool))
    print('[dex2jar] ' + ('(not specified)' if dex2jar is None else dex2jar))
    print('[deep search] ' + str(deep))
    print('[output] ' + output)

    # run all subtasks
    prepare()
    analyse_permissions()
    analyse_code_signature()
    analyse_ghidra()
    generate_output()
    clean()
    print('\n### finished ###\n')


def prepare():
    # create temporary folders
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    if not os.path.exists(ghidra_project):
        os.makedirs(ghidra_project)


def analyse_permissions():
    print('\n### analyse apk using apktool ###\n')
    temp_result = PermissionAnalyser.androidmanifest_script(temp_dir, apk, apktool, windows)

    # add to main result
    for apk_name, permissions in temp_result.items():
        apk_name = apk_name[apk_name.rfind('/')+1:]  # take only apk name
        check_apk_instance(apk_name)  # make sure that one instance exists
        for p in permissions:
            add_permission(apk_name, p)


def analyse_code_signature():
    print('\n### analyse apk using dex2jar ###\n')
    temp_result = CodeSignature.dex2jar(apk, dex2jar, windows)

    # add to main result
    for apk_name, apk_info in temp_result.items():
        apk_name = apk_name[apk_name.rfind('/')+1:]  # take only apk name
        check_apk_instance(apk_name)  # make sure that one instance exists
        for tracker_name, tracker_info in apk_info['trackers'].items():
            add_tracker(apk_name, tracker_name, tracker_info['website'], tracker_info['code_signature'], tracker_info['network_signature'], 'found code signature "'+tracker_info['code_signature']+'"')
        
        for info in apk_info['info']:
            add_info(apk_name, info)


def analyse_ghidra():
    print('\n### analyse apk using ghidra ###\n')
    if apk.endswith('.apk'):
        # single apk
        apk_name = apk[apk.rfind('/')+1:]
        check_apk_instance(apk_name)
        _analyse_ghidra(apk[:-4], apk_name)
    else:
        # directory (multiple apks)
        entries = os.listdir(apk)
        for e in entries:
            if os.path.isdir(apk+e):
                # check if corresponding apk exists
                exists = False
                for x in entries:
                    if str(x) == str(e)+'.apk':
                        exists = True
                        break
                if not exists:
                    continue

                # analyse
                apk_name = str(e)+'.apk'
                check_apk_instance(apk_name)
                _analyse_ghidra(apk+e, apk_name)


# analyse all dex files in folder
def _analyse_ghidra(directory, apk_name):

    print(' > ' + apk_name + '\n')

    # create folder for temporary ghidra project
    if not os.path.exists(ghidra_project):
            os.makedirs(ghidra_project)

    extension = '.bat' if windows else ''
    for path, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.dex'):
                dex = os.path.join(path, filename).replace('\\', '/')
                if deep:
                    subprocess.call(
                        [ghidra + 'support/analyzeHeadless' + extension, ghidra_project, 'temp.gpr', '-import', dex,
                        '-scriptPath', script_directory+'subtasks',
                        '-postScript','GhidraAPKScript.java', 'true',
                        '-deleteProject'])
                else:
                    # reduce analyse duration by disabling analysers in ghidra through pre script
                    subprocess.call(
                        [ghidra + 'support/analyzeHeadless' + extension, ghidra_project, 'temp.gpr', '-import', dex,
                        '-scriptPath', script_directory+'subtasks',
                        '-preScript', 'GhidraPreScript.java',
                        '-postScript','GhidraAPKScript.java', 'false',
                        '-deleteProject'])
    
                # read all the trackers from temporary output.csv
                datareader = csv.reader(open(script_directory+'subtasks/output.csv', 'r'), delimiter=',')
                for row in datareader:
                    add_tracker(apk_name, tracker_name = row[3], website = row[0], code_signature = row[1], network_signature = row[2], trigger = row[4])


def generate_output():
    print('\n### generate output ###\n')
    GenerateOutput.generate(output, result)
    webbrowser.open('file://' + output + 'result.html')


def clean():
    # delete csv
    csv_file = script_directory+'subtasks/output.csv'
    if os.path.exists(csv_file):
        os.remove(csv_file)

    # delete temporary files
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    # delete temporary ghidra project
    if os.path.exists(ghidra_project):
        shutil.rmtree(ghidra_project)


def check_apk_instance(apk_name):
    global result

    if apk_name not in result:
        print(' > adding "' + apk_name + '" to apk list\n')
        result[apk_name] = {
            'permissions': [],
            'trackers': {},
            'info': []
        }


def add_permission(apk_name, permission):
    if permission not in result[apk_name]['permissions']:
        print(' > adding permission "' + permission + "' to " + apk_name + '\n')
        result[apk_name]['permissions'].append(permission)
    else:
        print(' ERROR ! Permission script seems to have duplicates!')


def add_tracker(apk_name, tracker_name, website, code_signature, network_signature, trigger):
    if tracker_name not in result[apk_name]['trackers']:
        print(' > adding "' + tracker_name + "' as tracker to " + apk_name + '\n')
        result[apk_name]['trackers'][tracker_name] = {
            'website': website,
            'code_signature': code_signature,
            'network_signature': network_signature,
            'trigger': trigger
        }

def add_info(apk_name, info):
    print(' > ' + apk_name + ': ' + info + '\n')
    result[apk_name]['info'].append(info)


# run directly if this script is called from command line
# will not be called if imported from another script (in this case quickstart.py)
if __name__ == "__main__":
    init()
    