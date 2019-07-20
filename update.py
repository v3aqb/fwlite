
import os
import urllib.request
import glob
import zipfile

print('download fwlite-cli, fwlite-gui from github.')

print('download fwlite-cli')

urllib.request.urlretrieve('https://github.com/v3aqb/fwlite-cli/archive/master.zip', 'org.zip')

flist = glob.glob('fwlite/fwlite_cli/*.py')
for f in flist:
    os.remove(f)

with zipfile.ZipFile('org.zip') as z:
    namelist = z.namelist()
    namelist = [name for name in namelist if '/fwlite_cli/' in name]
    namelist = [name for name in namelist if '.py' in name]

    for name in namelist:
        data = z.open(name).read()
        _to = name.replace('fwlite-cli-master/', 'fwlite/')
        print(_to)
        with open(_to, 'wb') as f:
            f.write(data)

    data = z.open('fwlite-cli-master/config/config.ini').read()
    with open('conf/sample.ini', 'wb') as f:
        f.write(data)

os.remove('org.zip')

print('download fwlite-gui')

urllib.request.urlretrieve('https://github.com/v3aqb/fwlite-gui/archive/master.zip', 'org.zip')

flist = glob.glob('fwlite/fwlite_gui/*.py')
for f in flist:
    os.remove(f)

with zipfile.ZipFile('org.zip') as z:
    namelist = z.namelist()
    namelist = [name for name in namelist if '/fwlite_gui/' in name]
    namelist = [name for name in namelist if not name.endswith('/')]

    for name in namelist:
        data = z.open(name).read()
        _to = name.replace('fwlite-gui-master/', 'fwlite/')
        print(_to)
        with open(_to, 'wb') as f:
            f.write(data)

os.remove('org.zip')
