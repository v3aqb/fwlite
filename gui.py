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
        showToggleAction = QtGui.QAction("显示/隐藏", self, triggered=self.Message)
        proxyOverallAction = QtGui.QAction("全局代理", self, triggered=self.Message)
        proxyAutoAction = QtGui.QAction("自动代理", self, triggered=self.Message)
        proxyDirectAction = QtGui.QAction("直接连接", self, triggered=self.Message)

        trayIconMenu = QtGui.QMenu()

        trayIconMenu.addAction(showToggleAction)

        setproxyMenu = trayIconMenu.addMenu('设置代理')
        setproxyMenu.addAction(proxyOverallAction)
        setproxyMenu.addAction(proxyAutoAction)
        setproxyMenu.addAction(proxyDirectAction)

        advancedMenu = trayIconMenu.addMenu('高级')
        advancedMenu.addAction(QtGui.QAction("软件升级", self, triggered=self.Message))
        advancedMenu.addAction(QtGui.QAction("开机启动", self, triggered=self.Message))
        advancedMenu.addAction(QtGui.QAction("本地规则", self, triggered=self.Message))
        trayIconMenu.addSeparator()  # 间隔线
        trayIconMenu.addAction(QtGui.QAction("退出", self, triggered=QtGui.qApp.quit))

        self.setContextMenu(trayIconMenu)  # 右击托盘

    def trayClick(self, reason):

        if reason == QtGui.QSystemTrayIcon.DoubleClick:  # 双击
            self.showMessage()
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
