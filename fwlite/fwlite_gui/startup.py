
import os
import sys


def get_executable_path():
    # find FWLite.exe
    dir_ = os.path.dirname(sys.executable)

    target = os.path.join(dir_, 'FWLite.exe')
    if os.path.exists(target):
        return target
    target = os.path.join(os.path.dirname(dir_), 'FWLite.exe')
    if os.path.exists(target):
        return target
    raise ValueError('cannot find FWLite.exe')


def startup_status():
    from .knownpaths import get_path_by_name
    startup = get_path_by_name('Startup')
    path = os.path.join(startup, 'FWLite.lnk')
    # if shortcut not exist
    print(path)
    if not os.path.exists(path):
        return False
    return True


def set_startup(ifstartup):
    from .knownpaths import get_path_by_name
    startup = get_path_by_name('Startup')
    path = os.path.join(startup, 'FWLite.lnk')
    if ifstartup:
        # set startup shortcut
        if startup_status():
            os.remove(path)
        target = get_executable_path()
        target = os.path.abspath(target)
        create_shortcut(path, target)
    else:
        # delete startup shortcut
        os.remove(path)


def create_shortcut(path, target):
    from comtypes.client import CreateObject
    shell = CreateObject("WScript.Shell")
    from comtypes.gen import IWshRuntimeLibrary

    shortcut = shell.CreateShortcut(path).QueryInterface(IWshRuntimeLibrary.IWshShortcut)
    shortcut.TargetPath = target
    shortcut.WorkingDirectory = os.path.dirname(target)
    shortcut.Save()


def main():
    status = startup_status()
    print(status)
    set_startup(not status)


if __name__ == '__main__':
    main()
