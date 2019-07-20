import os
import glob

for f in glob.glob('*.ui'):
    fname = f.replace('\\', '/').split('/')[-1].split('.')[0]
    os.system('pyuic5 %s -o ./ui_%s.py' % (f, fname))

for path in glob.glob('ui_*.py'):
    with open(path, 'r') as f:
        data = f.read()
    with open(path, 'w') as f:
        data = data.replace('class ', 'from .translate import translate\n_tr = translate\n\n\nclass ')
        data = data.replace('_translate(', '_tr(')
        f.write(data)
