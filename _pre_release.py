#!/usr/bin/env python
# coding:utf-8

import os
import hashlib
import json
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
os.chdir(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))

if raw_input('update? y/n: ').lower().startswith('y'):
    updatelst = [('https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'),
                 ('https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.sample.ini'),
                 ('https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem'),
                 ('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'),
                 ]
    try:
        import urllib2
    except ImportError:
        import urllib.request as urllib2
    for url, path in updatelst:
        try:
            print 'downloading %s' % url
            r = urllib2.urlopen(url)
        except Exception as e:
            print repr(e)
        else:
            data = r.read()
            if r.getcode() == 200 and data:
                with open(path, 'wb') as localfile:
                    localfile.write(data)

BLOCKSIZE = 8192
v = {}
flist = ['./fgfw-lite/fgfw-lite.py',
         './fgfw-lite/encrypt.py',
         './fgfw-lite/cloud.txt',
         './userconf.sample.ini',
         './Python27/python27.zip',
         './README.md',
         './goagent/proxy.py',
         './goagent/proxy.sample.ini',
         './goagent/cacert.pem',
         ]

version = configparser.ConfigParser()
version.read('version.ini')

for f in flist:
    print 'hashing %s' % f
    hasher = hashlib.sha256()
    with open(f, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    v[f] = hasher.hexdigest()
    version.set('Update', f.replace('./', '').replace('/', '-'), v[f])

with open('./fgfw-lite/update.json', 'wb') as f:
    f.write(json.dumps(v, sort_keys=True, indent=4, separators=(',', ': ')))
with open('version.ini', 'w') as f:
    version.write(f)
raw_input('press Enter to exit...')
