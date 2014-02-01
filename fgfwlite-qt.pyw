#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import shlex
from PySide import QtCore, QtGui


WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/'))
os.chdir(WORKINGDIR)
TRAY_ICON = '%s/fgfw-lite/taskbar.ico' % WORKINGDIR
PYTHON = '%s/Python27/python27.exe' % WORKINGDIR if sys.platform.startswith('win') else '/usr/bin/env python2.7'


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(600, 480)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.textEdit = QtGui.QTextEdit(self.centralwidget)
        self.textEdit.setObjectName("textEdit")
        self.textEdit.setReadOnly(True)
        self.verticalLayout.addWidget(self.textEdit)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QtGui.QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.pushButton = QtGui.QPushButton(self.centralwidget)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)
        self.verticalLayout.addLayout(self.horizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "fgfwlite-qt", None, QtGui.QApplication.UnicodeUTF8))
        self.pushButton.setText(QtGui.QApplication.translate("MainWindow", "发送", None, QtGui.QApplication.UnicodeUTF8))


class MyThread(QtCore.QThread):
    trigger = QtCore.Signal(str)  # trigger传输的内容是字符串
    wtrigger = QtCore.Signal(str)

    def __init__(self, parent=None):
        super(MyThread, self).__init__(parent)

    def run(self):
        cmd = '%s %s/fgfw-lite/fgfw-lite.py -hide' % (PYTHON, WORKINGDIR)
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, startupinfo=startupinfo)
        self.wtrigger.connect(self.write)
        while self.process.poll() is None:
            self.trigger.emit(unicode(self.process.stdout.readline()).strip())

    def write(self, text):
        try:
            self.process.stdin.write(text)
            self.process.stdin.flush()
        except Exception:
            pass


class MainWindow(QtGui.QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.pushButton.clicked.connect(self.send)
        self.ui.lineEdit.returnPressed.connect(self.send)
        if os.name == 'nt':
            self.ui.textEdit.setStyleSheet("font: 9pt \"Consolas\";")
        else:
            self.ui.textEdit.setStyleSheet("font: 9pt \"Droid Sans Mono\";")
        self.setWindowIcon(QtGui.QIcon(TRAY_ICON))
        self.center()
        self.createActions()
        self.createTrayIcon()
        self.createProcess()

    def createProcess(self):
        self.thread = MyThread(self)
        self.thread.trigger.connect(self.update_text)
        self.thread.start()

    def center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def createActions(self):
        self.showToggleAction = QtGui.QAction(u"显示/隐藏", self, triggered=self.showToggle)
        self.reloadAction = QtGui.QAction(u"重新载入", self, triggered=self.reload)
        self.quitAction = QtGui.QAction(u"退出", self, triggered=self.on_Quit)

    def createTrayIcon(self):
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.showToggleAction)
        self.trayIconMenu.addAction(self.reloadAction)
        self.trayIconMenu.addSeparator()
        self.trayIconMenu.addAction(self.quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(self)
        self.trayIcon.setContextMenu(self.trayIconMenu)
        self.trayIcon.setIcon(QtGui.QIcon(TRAY_ICON))
        self.trayIcon.activated.connect(self.on_trayActive)
        self.trayIcon.show()

    def closeEvent(self, event):
        if self.trayIcon.isVisible():
            self.hide()
        event.ignore()

    def on_trayActive(self, reason):
        if reason is self.trayIcon.Trigger:
            self.showToggle()

    def on_Quit(self):
        self.thread.wtrigger.emit('sys.exit()\n')
        self.thread.wait()
        QtGui.qApp.quit()

    def send(self):
        te = self.ui.lineEdit.text()
        self.ui.lineEdit.clear()
        self.thread.wtrigger.emit(te + '\n')
        self.update_text(te)

    def update_text(self, text):
        if text:
            if len(self.ui.textEdit.toPlainText().splitlines()) > 300:
                self.ui.textEdit.setPlainText(u'\n'.join(self.ui.textEdit.toPlainText().splitlines()[-100:]))
            self.ui.textEdit.moveCursor(QtGui.QTextCursor.End)
            self.ui.textEdit.append(text)

    def showToggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.activateWindow()

    def reload(self):
        self.thread.wtrigger.emit('sys.exit()\n')
        self.thread.wait()
        self.ui.textEdit.clear()
        self.createProcess()

if __name__ == "__main__":
    app = QtGui.QApplication('')
    win = MainWindow()
    sys.exit(app.exec_())
