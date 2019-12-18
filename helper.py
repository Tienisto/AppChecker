def digest_path(path, append_slash=True):
    if append_slash and not path.endswith('/'):
        return (path+'/').replace('\\', '/')
    else:
        return path.replace('\\', '/')
