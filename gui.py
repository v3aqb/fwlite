#! /usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals

import sys
from PySide import QtGui


class Window(QtGui.QSystemTrayIcon):

    def __init__(self):

        super(Window, self).__init__()

        icon = QtGui.QIcon("./include/taskbar.ico")

        self.setIcon(icon)
        self.show()

        self.activated.connect(self.trayClick)  # 点击托盘

        self.setToolTip("托盘小程序")  # 托盘信息

        self.Menu()  # 右键菜单

    def Menu(self):

        self.minimizeAction = QtGui.QAction("最小化", self, triggered=self.Message)
        self.maximizeAction = QtGui.QAction("最大化", self, triggered=self.Message)
        self.restoreAction = QtGui.QAction("还原", self, triggered=self.Message)
        self.quitAction = QtGui.QAction("退出", self, triggered=QtGui.qApp.quit)

        self.trayIconMenu = QtGui.QMenu()

        self.trayIconMenu.addAction(self.minimizeAction)
        self.trayIconMenu.addAction(self.maximizeAction)
        self.trayIconMenu.addAction(self.restoreAction)
        self.trayIconMenu.addSeparator()  # 间隔线
        self.trayIconMenu.addAction(self.quitAction)

        self.setContextMenu(self.trayIconMenu)  # 右击托盘

    def trayClick(self, reason):

        if reason == QtGui.QSystemTrayIcon.DoubleClick:  # 双击
            self.showNormal()
        elif reason == QtGui.QSystemTrayIcon.MiddleClick:  # 中击
            self.showMessage()
        else:
            pass

    def Message(self):
        icon = QtGui.QSystemTrayIcon.Information
        self.showMessage("提示信息", "点我干嘛？", icon)

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    frm = Window()
    sys.exit(app.exec_())
