
import os
import urllib.request
import glob
import zipfile

print('update from github...')

print('download hxcrypto')

urllib.request.urlretrieve('https://github.com/v3aqb/hxcrypto/archive/master.zip', 'org.zip')

flist = glob.glob('fwlite/hxcrypto/*.*')
for f in flist:
    os.remove(f)

with zipfile.ZipFile('org.zip') as z:
    namelist = z.namelist()
    namelist = [name for name in namelist if '/hxcrypto/' in name]
    namelist = [name for name in namelist if not name.endswith('/')]

    for name in namelist:
        if 'ctypes_libsodium' in name:
            continue
        data = z.open(name).read()
        _to = name.replace('hxcrypto-master/', 'fwlite/')
        print(_to)
        with open(_to, 'wb') as f:
            f.write(data)

os.remove('org.zip')

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


print('download hxsocks')

urllib.request.urlretrieve('https://github.com/v3aqb/hxsocks/archive/master.zip', 'org.zip')

if not os.path.isdir('fwlite/hxsocks'):
    if os.path.exists('fwlite/hxsocks'):
        os.remove('fwlite/hxsocks')
    os.mkdir('fwlite/hxsocks')

flist = glob.glob('fwlite/hxsocks/*.py')
for f in flist:
    os.remove(f)

with zipfile.ZipFile('org.zip') as z:
    namelist = z.namelist()
    namelist = [name for name in namelist if '/hxsocks/' in name]
    namelist = [name for name in namelist if not name.endswith('/')]

    for name in namelist:
        data = z.open(name).read()
        _to = name.replace('hxsocks-master/', 'fwlite/')
        print(_to)
        with open(_to, 'wb') as f:
            f.write(data)

os.remove('org.zip')

urllib.request.urlretrieve('https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt', './conf/gfwlist.txt')

with open('./conf/gfwlist.txt') as f:
    data = f.read()
    if '!' not in data:
        import base64
        data = ''.join(data.split())
        data = base64.b64decode(data).decode()
with open('./conf/gfwlist.txt', 'w') as f:
    f.write(data)

urllib.request.urlretrieve('https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt', './conf/china_ip_list.txt')

urllib.request.urlretrieve('https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chnroute-v6.txt', './conf/china_ip_list_v6.txt')

urllib.request.urlretrieve('https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/basic/hosts', './conf/adblock.txt')

urllib.request.urlretrieve('https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chinalist.txt', './conf/chinalist.txt')
