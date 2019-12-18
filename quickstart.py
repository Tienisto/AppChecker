import argparse
import os
from helper import *
from main import run

dependencies = digest_path(os.path.dirname(os.path.realpath(__file__)).replace('\\','/'))+'dependencies/'  # path to all programs

parser = argparse.ArgumentParser(description='Generic Exodus: Analyse APKs (QUICKSTART)')
parser.add_argument('-a', '--apk', help='path to apk file', required=True)
parser.add_argument('-o', '--output', help='path to output folder', required=False)
parser.add_argument('-f', '--force-deep-search', action='store_true')
args = vars(parser.parse_args())

post_args = {
    'apk': args['apk'],
    'ghidra': dependencies+'ghidra/',  # predefined ghidra path
    'apktool': dependencies+'apktool/',  # predefined apktool path
    'dex2jar': dependencies+'dex2jar/',  # predefined dex2jar path
    'output': args['output'],
    'force_deep_search': args['force_deep_search']
}

run(post_args)