import hashlib
from datetime import datetime
import os
import shutil
from stat import S_IREAD, S_IRGRP, S_IROTH
import stat

TS_MULT = 10**9
BLOCKLENGTH = 262144

def make_file_read_only(path):
    os.chmod(path, S_IREAD|S_IRGRP|S_IROTH)
        
def open_file(root_path, name, temp_path=None):
    if not temp_path:
        temp_path = root_path
        
    if name.startswith('.'):
        #we ignore files starting with a dot when inspecting
        #the stash, so we don't want to use such a name for a
        #file we care about
        name = '_'+name
    
    temp_file_name = datetime.now().strftime('%Y%m%d%H%M%S%f')
    temp_file_path = os.path.join(temp_path, temp_file_name)
    temp_file = open(temp_file_path, 'wb')
    return {'file': temp_file,
            'name': name,
            'root_path': root_path,
            'temp_file_path': temp_file_path,
            'hasher': hashlib.sha256(),
            'hashing_started': int(datetime.now().timestamp()*TS_MULT),
            'bytes_hashed': 0}

def write_to_file(record, data):
    record['file'].write(data)
    record['hasher'].update(data)
    record['bytes_hashed'] = record['bytes_hashed'] + len(data)

def abort_file(record):
    record['file'].close()
    os.remove(record['temp_file_path'])

def save_file(record):
    record['file'].close()
    sha256 = record['hasher'].hexdigest()
    record['sha256'] = sha256
    record['hashing_completed'] = int(datetime.now().timestamp()*TS_MULT)

    del record['file']
    del record['hasher']

    new_dir_path = hash2path(record['root_path'], sha256)
    if not os.path.exists(new_dir_path):
        os.makedirs(new_dir_path)
        new_file_path = os.path.join(new_dir_path, record['name'])
        shutil.move(record['temp_file_path'], new_file_path)
        make_file_read_only(new_file_path)
        record['new'] = True
    else: #data is already in hash store
        os.remove(record['temp_file_path'])
        record['new'] = False
        

def hash_file(path):
    hash_rec = {}
    hasher = hashlib.sha256()
    byte_count = 0
    hash_rec['hashing_started'] = int(datetime.now().timestamp()*TS_MULT)
    with open(path, 'rb') as fb:
        byte_block = fb.read(BLOCKLENGTH)
        while len(byte_block) > 0:
            byte_count = byte_count + len(byte_block)
            hasher.update(byte_block)
            byte_block = fb.read(BLOCKLENGTH)
    hash_rec['sha256'] = hasher.hexdigest()
    hash_rec['hashing_completed'] = int(datetime.now().timestamp()*TS_MULT)
    hash_rec['bytes_hashed'] = byte_count
    
    return hash_rec
        
def move_file(root_path, file_path):
    hash_rec = hash_file(file_path)
    new_dir_path = hash2path(root_path, hash_rec['sha256'])
    if not os.path.exists(new_dir_path):
        os.makedirs(new_dir_path)
        name = os.path.basename(file_path)
        new_file_path = os.path.join(new_dir_path, name)
        shutil.move(file_path, new_file_path)
        make_file_read_only(new_file_path)
        hash_rec['new'] = True
    else:
        #file already exists
        hash_rec['new'] = False
    return hash_rec

def check_file(root_path, hsh, num_bytes=False):
    path = hash2filepath(root_path, hsh)
    if not path:
        return False
    hasher = hashlib.sha256()
    byte_count = 0
    with open(path, 'rb') as fb:
        byte_block = fb.read(BLOCKLENGTH)
        while len(byte_block) > 0:
            byte_count = byte_count + len(byte_block)
            hasher.update(byte_block)
            byte_block = fb.read(BLOCKLENGTH)
    sha256 = hasher.hexdigest()
    if hsh != sha256:
        print('hash does not match:')
        print('record_hash={}'.format(hsh))
        print('stored_hash={}'.format(sha256))
        return False
    if num_bytes and (num_bytes != byte_count):
        print('num bytes does not match:')
        print('record={}'.format(num_bytes))
        print('stored={}'.format(byte_count))
        return False
    return True

def delete_file(root_path, hsh):
    dir_path = hash2path(root_path, hsh)
    if not os.path.exists(dir_path):
        print('directory {} does not exist'.format(dir_path))
        return False
    
    for f in os.listdir(dir_path):
        if not os.path.isfile(os.path.join(dir_path, f)):
            print('directory {} contains something other than '
                  'a regular file'.format(dir_path))
            print(os.path.join(dir_path, f))
            return False
    
    for f in os.listdir(dir_path):
        os.remove(os.path.join(dir_path, f))
        
    os.removedirs(dir_path)
    return True


def path2hash(root_path, path):
    #container dir path to hash
    rp = os.path.relpath(path, start=root_path)
    return ''.join(os.path.normpath(rp).split(os.path.sep))

def hash2path(root_path, hsh):
    #hash to container dir path
    parts = (hsh[0:2], hsh[2:4], hsh[4:6], hsh[6:8], hsh[8:])
    return os.path.join(root_path, *parts)

def hash2filepath(root_path, hsh):
    dir_path = hash2path(root_path, hsh)
    if not os.path.exists(dir_path):
        print('directory {} does not exist'.format(dir_path))
        return False
    
    # we ignore files starting with a dot e.g. .DS_Store
    ls = [f for f in os.listdir(dir_path) if not f.startswith('.')]
    
    if len(ls) == 0:
        print('directory exists but is empty')
        return False
    if len(ls) > 1:
        print('directory exists but contains more than one file!')
        return False
    return os.path.join(dir_path, ls[0])