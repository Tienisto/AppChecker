#TODO: Search in AndroidManifest.xml for permissions
import subprocess
import os
import sys
import csv
from xml.dom import minidom

def androidmanifest_script(temp_dir, workspace_dir, apktool_path,is_windows):
##################################################################################
# get AndroidManifest from .apk file or from all .apk files in dir
#################################################################################
	if is_windows is True:
		print('You are using a Windows System.')
		command_postfix = ".bat"
	else:
		print('You are using a UNIX System.')
		command_postfix = ''

	if workspace_dir.endswith('.apk'):
		permissionlist=[]
		permissiondictonary={}
		print('You choose a single .apk file.')
		decode_path = temp_dir+workspace_dir+'_decode'
		print('Using apktool on ',workspace_dir,'...')
		print('The apktool will save the data at ', decode_path)
		subprocess.call([apktool_path + 'apktool' + command_postfix,'decode', workspace_dir, '-o', decode_path,'-f'])
		androidmanifest_path = os.path.join(decode_path,'AndroidManifest.xml')
		permissionlist = permissions(androidmanifest_path)
		permissiondictonary[decode_path[:-7]]=permissionlist
		return permissiondictonary

	else:
		print('You choose a directory.')
		all_files = []
		# ls workspace
		for path, subdirs, files in os.walk(workspace_dir):
			for filename in files:
				f = os.path.join(path, filename)
				all_files.append(str(f))
		permissionlist=[]
		permissiondictonary={}
		for i in all_files:
			# find all .apk files
			if i.endswith('.apk'):
				print('Using apktool on ',i,'...')
				decode_path = temp_dir+i+'_decode'
				print('The apktool will save the data at ', decode_path)
				subprocess.call([apktool_path + 'apktool' + command_postfix,'decode', i, '-o', decode_path,'-f'])
				# TODO: read AndroidManifest and find permissions
				androidmanifest_path = os.path.join(decode_path,'AndroidManifest.xml')
				permissionlist= permissions(androidmanifest_path)
				permissiondictonary[i]=permissionlist
		return permissiondictonary			

#search for permissions
def permissions(androidmanifest_path):					
	with open(androidmanifest_path) as f:
		xmldoc = minidom.parse(f)
		permissionlist = xmldoc.getElementsByTagName('uses-permission')
		permissionvalue = [] 
		for i in range(len(permissionlist)):
			permissionvalue.append(permissionlist[i].attributes['android:name'].value)
	return permissionvalue
