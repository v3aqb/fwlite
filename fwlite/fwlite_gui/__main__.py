import os
import sys
import argparse
from PyQt5 import QtGui
from PyQt5.QtWidgets import QApplication
from .mainw import MainWindow


def main():
    if os.name == 'nt':
        import ctypes
        myappid = 'v3aqb.fwlite'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="path to config file")
    args = parser.parse_args()

    app = QApplication([])
    font = QtGui.QFont()
    if sys.platform.startswith('win'):
        font.setFamily("Consolas")
    elif sys.platform.startswith('linux'):
        font.setFamily("Droid Sans Mono")
    elif sys.platform.startswith('darwin'):
        font.setFamily("Menlo")
    app.setFont(font)

    ex = MainWindow(args.c)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
