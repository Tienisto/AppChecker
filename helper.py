def digest_path(path, append_slash=True):
    if append_slash and not path.endswith('/'):
        return (path+'/').replace('\\', '/')
    else:
        return path.replace('\\', '/')

def get_file_name(path):
    slash_index = path.rfind('/')
    if slash_index == -1:
        return path
    else:
        return path[slash_index+1:]